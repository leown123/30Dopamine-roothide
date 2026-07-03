#include <libjailbreak/libjailbreak.h>
#include <mach-o/dyld.h>
#include <xpc/xpc.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <sandbox.h>
#include <substrate.h>
#include <libjailbreak/jbserver.h>

#include <bsm/audit.h> // for audit_token_t

mach_msg_header_t* dispatch_mach_msg_get_msg(void *message, size_t *_Nullable size_ptr);
int jbserver_received_mach_message(audit_token_t *auditToken, struct jbserver_mach_msg *jbsMachMsg);
int jbserver_received_complex_mach_message(audit_token_t *auditToken, uint64_t action, struct jbserver_mach_complex_msg *jbsMachMsg);

int xpc_receive_mach_msg(void *msg, void *a2, void *a3, void *a4, xpc_object_t *xOut);
int (*xpc_receive_mach_msg_orig)(void *msg, void *a2, void *a3, void *a4, xpc_object_t *xOut);

// 你可能需要实现的辅助函数：从 xpc_object_t 提取目标服务名
static const char* xpc_dictionary_get_service_name(xpc_object_t xdict) {
    // XPC 消息中通常包含 "service" 键，指向目标服务名
    xpc_object_t svc = xpc_dictionary_get_value(xdict, "service");
    if (svc && xpc_get_type(svc) == XPC_TYPE_STRING) {
        return xpc_string_get_string_ptr(svc);
    }
    return NULL;
}

// 你希望拒绝的黑名单进程可能请求的服务名列表
// 例如：某些 Apple 服务可能被用于检测
static bool is_restricted_service_for_blacklist(const char *service_name) {
    if (!service_name) return false;
    // 示例：拒绝访问 com.apple.xxx.detect 之类的服务
    if (strstr(service_name, "com.apple.amfid") != NULL) return true;
	if (strstr(service_name, "com.apple.securityd") != NULL) return true;
	if (strstr(service_name, "com.apple.ocspd") != NULL) return true;

	if (strstr(service_name, "com.apple.sysdiagnose") != NULL) return true;
	if (strstr(service_name, "com.apple.agg") != NULL) return true;
	if (strstr(service_name, "com.apple.coreduetd") != NULL) return true;

	if (strstr(service_name, "com.apple.powerlogd") != NULL) return true;
	if (strstr(service_name, "com.apple.logd") != NULL) return true;
	if (strstr(service_name, "com.apple.osanalytics") != NULL) return true;

	if (strstr(service_name, "com.apple.tccd") != NULL) return true;
	if (strstr(service_name, "com.apple.locationd") != NULL) return true;
	if (strstr(service_name, "com.apple.mobilesafari") != NULL) return true;
	if (strstr(service_name, "com.apple.accountsd") != NULL) return true;

	if (strstr(service_name, "com.apple.containermanagerd") != NULL) return true;
	if (strstr(service_name, "com.apple.launchservicesd") != NULL) return true;
	if (strstr(service_name, "com.apple.installd") != NULL) return true;

	if (strstr(service_name, "com.apple.iokitd") != NULL) return true;
	if (strstr(service_name, "com.apple.mobileassetd") != NULL) return true;
	
    // 也可以拒绝所有非越狱相关的服务？需根据需求定制
    return false;
}


int xpc_receive_mach_msg_hook(void *msg, void *a2, void *a3, void *a4, xpc_object_t *xOut)
{
	size_t msgBufSize = 0;
    struct jbserver_mach_msg *jbsMachMsg = (struct jbserver_mach_msg *)dispatch_mach_msg_get_msg(msg, &msgBufSize);
	bool wasProcessed = false;
    if (jbsMachMsg != NULL && msgBufSize >= sizeof(mach_msg_header_t)) {
        size_t msgSize = jbsMachMsg->hdr.msgh_size;
        if (msgSize <= msgBufSize && msgSize >= sizeof(struct jbserver_mach_msg) && jbsMachMsg->magic == JBSERVER_MACH_MAGIC) {
			mach_msg_context_trailer_t *trailer = (mach_msg_context_trailer_t *)((uint8_t *)jbsMachMsg + round_msg(jbsMachMsg->hdr.msgh_size));
            jbserver_received_mach_message(&trailer->msgh_audit, jbsMachMsg);
			wasProcessed = true;
            // Pass the message to xpc_receive_mach_msg anyway, it will get rid of it for us
        }
    }
	// Not needed, since we don't have any complex messages at the moment
	/*struct jbserver_mach_complex_msg *jbsComplexMachMsg = (struct jbserver_mach_complex_msg *)jbsMachMsg;
	if (!wasProcessed && jbsComplexMachMsg != NULL && msgBufSize >= sizeof(struct jbserver_mach_complex_msg)) {
		// Warning: Witchcraft incoming
		size_t msgSize = jbsComplexMachMsg->hdr.msgh_size;
		if (jbsComplexMachMsg->hdr.msgh_bits & MACH_MSGH_BITS_COMPLEX) {
			uintptr_t magicOff = sizeof(struct jbserver_mach_complex_msg) + (jbsComplexMachMsg->body.msgh_descriptor_count * sizeof(mach_msg_port_descriptor_t));
			uintptr_t actionOff = magicOff + sizeof(uint64_t);
			if (msgSize >= (actionOff + sizeof(uint64_t))) {
				uint64_t magic = *(uint64_t *)(((uintptr_t)jbsComplexMachMsg) + magicOff);
				if (magic == JBSERVER_MACH_MAGIC) {
					uint64_t action = *(uint64_t *)(((uintptr_t)jbsComplexMachMsg) + actionOff);
					mach_msg_context_trailer_t *trailer = (mach_msg_context_trailer_t *)((uint8_t *)jbsComplexMachMsg + round_msg(jbsComplexMachMsg->hdr.msgh_size));
					jbserver_received_complex_mach_message(&trailer->msgh_audit, action, jbsComplexMachMsg);
					wasProcessed = true;
            		// Pass the message to xpc_receive_mach_msg anyway, it will get rid of it for us
				}
			}
		}
	}*/

	/*
	int r = xpc_receive_mach_msg_orig(msg, a2, a3, a4, xOut);
	if (!wasProcessed && r == 0 && xOut && *xOut) {
		if (jbserver_received_xpc_message(&gGlobalServer, *xOut) == 0) {
			// Returning non null here makes launchd disregard this message
			// For jailbreak messages we have the logic to handle them
			xpc_release(*xOut);
			return 22;
		}
	}
	*/

	int r = xpc_receive_mach_msg_orig(msg, a2, a3, a4, xOut);
    if (!wasProcessed && r == 0 && xOut && *xOut) {
        // 检查发送者是否黑名单
        //if (isBlacklistedToken(*xOut)) {
            // 提取目标服务名
            const char *svcName = xpc_dictionary_get_service_name(*xOut);
            if (is_restricted_service_for_blacklist(svcName)) {
                //JBLogDebug("blocked XPC service '%s' from blacklisted pid %d", svcName ? svcName : "(null)", audit_token_to_pid(senderAuditToken));
                xpc_release(*xOut);
                *xOut = NULL;
                return 22; // 返回 EINVAL 让 launchd 丢弃
            }
        //}

        // 正常检查越狱服务器 XPC 消息（不是 mach 消息那种）
        if (jbserver_received_xpc_message(&gGlobalServer, *xOut) == 0) {
            xpc_release(*xOut);
            return 22;
        }
    }


	
	return r;
}

void initXPCHooks(void)
{
	MSHookFunction(xpc_receive_mach_msg, (void *)xpc_receive_mach_msg_hook, (void **)&xpc_receive_mach_msg_orig);
}
