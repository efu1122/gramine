/* SPDX-License-Identifier: LGPL-3.0-or-later */
/* Copyright (C) 2014 Stony Brook University
 * Copyright (C) 2020 Intel Corporation
 *                    Borys Popławski <borysp@invisiblethingslab.com>
 */

#include "api.h"
#include "libos_internal.h"
#include "libos_lock.h"
#include "libos_table.h"
#include "libos_thread.h"
#include "libos_types.h"

long libos_syscall_getuid(void) {
    struct libos_thread* current = get_cur_thread();
    lock(&current->lock);
    uid_t uid = current->uid;
    unlock(&current->lock);
    return uid;
}

long libos_syscall_getgid(void) {
    struct libos_thread* current = get_cur_thread();
    lock(&current->lock);
    gid_t gid = current->gid;
    unlock(&current->lock);
    return gid;
}

long libos_syscall_geteuid(void) {
    struct libos_thread* current = get_cur_thread();
    lock(&current->lock);
    uid_t euid = current->euid;
    unlock(&current->lock);
    return euid;
}

long libos_syscall_getegid(void) {
    struct libos_thread* current = get_cur_thread();
    lock(&current->lock);
    gid_t egid = current->egid;
    unlock(&current->lock);
    return egid;
}

long libos_syscall_setuid(uid_t uid) {
    int ret;
    struct libos_thread* current = get_cur_thread();

    lock(&current->lock);
    if (current->uid == 0) {
        /* if the user is root, the real UID and saved set-user-ID are also set */
        current->uid  = uid;
        current->suid = uid;
    } else if (uid != current->uid && uid != current->suid) {
        ret = -EPERM;
        goto out;
    }
    current->euid = uid;
    ret = 0;
out:
    unlock(&current->lock);
    return ret;
}

long libos_syscall_setgid(gid_t gid) {
    int ret;
    struct libos_thread* current = get_cur_thread();

    lock(&current->lock);
    if (current->uid == 0) {
        /* if the user is root, the real GID and saved set-group-ID are also set */
        current->gid  = gid;
        current->sgid = gid;
    } else if (gid != current->gid && gid != current->sgid) {
        ret = -EPERM;
        goto out;
    }
    current->egid = gid;
    ret = 0;
out:
    unlock(&current->lock);
    return ret;
}

long libos_syscall_setreuid(uid_t ruid, uid_t euid) {
    int ret;
    struct libos_thread* current = get_cur_thread();

    lock(&current->lock);
    if (current->euid != 0) {
        /* unprivileged user */
        if (ruid != -1 && ruid != current->uid && ruid != current->euid) {
            ret = -EPERM;
            goto out;
        }
        if (euid != -1 && euid != current->uid && euid != current->euid && euid != current->suid) {
            ret = -EPERM;
            goto out;
        }
    }

    if (ruid != -1 && ruid != current->uid || euid != -1 && euid != current->uid) {
        /* If the real user ID is set or the effective user ID is set to a value not equal to the
         * previous real user ID, the saved set-user-ID will be set to the new effective user ID.*/
        current->suid = euid;
    }

    if (ruid != -1)
        current->uid = ruid;
    if (euid != -1)
        current->euid = euid;
    ret = 0;
out:
    unlock(&current->lock);
    return ret;
}

long libos_syscall_setregid(gid_t rgid, gid_t egid) {
    int ret;
    struct libos_thread* current = get_cur_thread();

    lock(&current->lock);
    if (current->euid != 0) {
        /* unprivileged user */
        if (rgid != -1 && rgid != current->gid && rgid != current->egid) {
            ret = -EPERM;
            goto out;
        }
        if (egid != -1 && egid != current->gid && egid != current->egid && egid != current->sgid) {
            ret = -EPERM;
            goto out;
        }
    }

    if (rgid != -1 && rgid != current->gid || egid != -1 && egid != current->gid) {
        /* If the real user ID is set or the effective user ID is set to a value not equal to the
         * previous real user ID, the saved set-user-ID will be set to the new effective user ID.*/
        current->sgid = egid;
    }

    if (rgid != -1)
        current->gid = rgid;
    if (egid != -1)
        current->egid = egid;
    ret = 0;
out:
    unlock(&current->lock);
    return ret;
}

#define NGROUPS_MAX 65536 /* # of supplemental group IDs; has to be same as host OS */

long libos_syscall_setgroups(int gidsetsize, gid_t* grouplist) {
    if (gidsetsize < 0 || (unsigned int)gidsetsize > NGROUPS_MAX)
        return -EINVAL;

    struct libos_thread* current = get_cur_thread();
    if (gidsetsize == 0) {
        free(current->groups_info.groups);
        current->groups_info.groups = NULL;
        current->groups_info.count = 0;
        return 0;
    }

    if (!is_user_memory_readable(grouplist, gidsetsize * sizeof(gid_t)))
        return -EFAULT;

    size_t groups_len = (size_t)gidsetsize;
    gid_t* groups = (gid_t*)malloc(groups_len * sizeof(*groups));
    if (!groups) {
        return -ENOMEM;
    }
    for (size_t i = 0; i < groups_len; i++) {
        groups[i] = grouplist[i];
    }

    void* old_groups = NULL;
    current->groups_info.count = groups_len;
    old_groups = current->groups_info.groups;
    current->groups_info.groups = groups;

    free(old_groups);

    return 0;
}

long libos_syscall_getgroups(int gidsetsize, gid_t* grouplist) {
    if (gidsetsize < 0)
        return -EINVAL;

    if (!is_user_memory_writable(grouplist, gidsetsize * sizeof(gid_t)))
        return -EFAULT;

    struct libos_thread* current = get_cur_thread();
    size_t ret_size = current->groups_info.count;

    if (gidsetsize) {
        if (ret_size > (size_t)gidsetsize) {
            return -EINVAL;
        }

        for (size_t i = 0; i < ret_size; i++) {
            grouplist[i] = current->groups_info.groups[i];
        }
    }

    return (int)ret_size;
}

long libos_syscall_setresuid(uid_t ruid, uid_t euid, uid_t suid) {
    int ret;
    struct libos_thread* current = get_cur_thread();

    lock(&current->lock);
    if (current->euid != 0) {
        /* unprivileged user */
        if (ruid != -1 && ruid != current->uid && ruid != current->euid && ruid != current->suid) {
            ret = -EPERM;
            goto out;
        }
        if (euid != -1 && euid != current->uid && euid != current->euid && euid != current->suid) {
            ret = -EPERM;
            goto out;
        }
        if (suid != -1 && suid != current->uid && suid != current->euid && suid != current->suid) {
            ret = -EPERM;
            goto out;
        }
    }
    if (ruid != -1)
        current->uid  = ruid;
    if (euid != -1)
        current->euid = euid;
    if (suid != -1)
        current->suid = suid;
    ret = 0;
out:
    unlock(&current->lock);
    return ret;
}

long libos_syscall_getresuid(uid_t* ruid, uid_t* euid, uid_t* suid) {
    if (!is_user_memory_writable(ruid, sizeof(*ruid)) ||
        !is_user_memory_writable(euid, sizeof(*euid)) ||
        !is_user_memory_writable(suid, sizeof(*suid)))
        return -EFAULT;

    struct libos_thread* current = get_cur_thread();
    lock(&current->lock);
    *ruid = current->uid;
    *euid = current->euid;
    *suid = current->suid;
    unlock(&current->lock);
    return 0;
}

long libos_syscall_setresgid(gid_t rgid, gid_t egid, gid_t sgid) {
    int ret;
    struct libos_thread* current = get_cur_thread();

    lock(&current->lock);
    if (current->euid != 0) {
        /* unprivileged user */
        if (rgid != -1 && rgid != current->gid && rgid != current->egid && rgid != current->sgid) {
            ret = -EPERM;
            goto out;
        }
        if (egid != -1 && egid != current->gid && egid != current->egid && egid != current->sgid) {
            ret = -EPERM;
            goto out;
        }
        if (sgid != -1 && sgid != current->gid && sgid != current->egid && sgid != current->sgid) {
            ret = -EPERM;
            goto out;
        }
    }
    if (rgid != -1)
        current->gid  = rgid;
    if (egid != -1)
        current->egid = egid;
    if (sgid != -1)
        current->sgid = sgid;
    ret = 0;
out:
    unlock(&current->lock);
    return ret;
}

long libos_syscall_getresgid(gid_t* rgid, gid_t* egid, gid_t* sgid) {
    if (!is_user_memory_writable(rgid, sizeof(*rgid)) ||
        !is_user_memory_writable(egid, sizeof(*egid)) ||
        !is_user_memory_writable(sgid, sizeof(*sgid)))
        return -EFAULT;

    struct libos_thread* current = get_cur_thread();
    lock(&current->lock);
    *rgid = current->gid;
    *egid = current->egid;
    *sgid = current->sgid;
    unlock(&current->lock);
    return 0;
}
