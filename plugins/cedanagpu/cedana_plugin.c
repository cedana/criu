#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <linux/limits.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <stdint.h>
#include <pthread.h>
#include <semaphore.h>

#include "criu-plugin.h"
#include "plugin.h"
#include "xmalloc.h"
#include "criu-log.h"
#include "files.h"

#include "common/list.h"

#include "img-streamer.h"
#include "image.h"
#include "cr_options.h"

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "cedana_plugin: "

#ifdef DEBUG
#define plugin_log_msg(fmt, ...) pr_debug(fmt, ##__VA_ARGS__)
#else
#define plugin_log_msg(fmt, ...) \
	{                        \
	}
#endif


int write_fp(FILE *fp, const void *buf, const size_t buf_len)
{
	size_t len_write;

	len_write = fwrite(buf, 1, buf_len, fp);
	if (len_write != buf_len) {
		pr_perror("Unable to write file (wrote:%ld buf_len:%ld)", len_write, buf_len);
		return -EIO;
	}
	return 0;
}

int read_fp(FILE *fp, void *buf, const size_t buf_len)
{
	size_t len_read;

	len_read = fread(buf, 1, buf_len, fp);
	if (len_read != buf_len) {
		pr_perror("Unable to read file (read:%ld buf_len:%ld)", len_read, buf_len);
		return -EIO;
	}
	return 0;
}

/**
 * @brief Open an image file
 *
 * We store the size of the actual contents in the first 8-bytes of the file. This allows us to
 * determine the file size when using criu_image_streamer when fseek and fstat are not available.
 * The FILE * returned is already at the location of the first actual contents.
 *
 * @param path The file path
 * @param write False for read, true for write
 * @param size Size of actual contents
 * @return FILE *if successful, NULL if failed
 */
FILE *open_img_file(char *path, bool write, size_t *size)
{
	FILE *fp = NULL;
	int fd, ret;

	if (opts.stream)
		fd = img_streamer_open(path, write ? O_DUMP : O_RSTR);
	else
		fd = openat(criu_get_image_dir(), path, write ? (O_WRONLY | O_CREAT) : O_RDONLY, 0600);

	if (fd < 0) {
		pr_perror("%s: Failed to open for %s", path, write ? "write" : "read");
		return NULL;
	}

	fp = fdopen(fd, write ? "w" : "r");
	if (!fp) {
		pr_perror("%s: Failed get pointer for %s", path, write ? "write" : "read");
		return NULL;
	}

	if (write)
		ret = write_fp(fp, size, sizeof(*size));
	else
		ret = read_fp(fp, size, sizeof(*size));

	if (ret) {
		pr_perror("%s:Failed to access file size", path);
		fclose(fp);
		return NULL;
	}

	pr_debug("%s:Opened file for %s with size:%ld\n", path, write ? "write" : "read", *size);
	return fp;
}

/**
 * @brief Write an image file
 *
 * We store the size of the actual contents in the first 8-bytes of the file. This allows us to
 * determine the file size when using criu_image_streamer when fseek and fstat are not available.
 *
 * @param path The file path
 * @param buf pointer to data to be written
 * @param buf_len size of buf
 * @return 0 if successful. -errno on failure
 */
int write_img_file(char *path, const void *buf, const size_t buf_len)
{
	int ret;
	FILE *fp;
	size_t len = buf_len;

	fp = open_img_file(path, true, &len);
	if (!fp)
		return -errno;

	ret = write_fp(fp, buf, buf_len);
	fclose(fp); /* this will also close fd */
	return ret;
}

int read_file(const char *file_path, void *buf, const size_t buf_len)
{
	int ret;
	FILE *fp;

	fp = fopen(file_path, "r");
	if (!fp) {
		pr_perror("Cannot fopen %s", file_path);
		return -errno;
	}

	ret = read_fp(fp, buf, buf_len);
	fclose(fp); /* this will also close fd */
	return ret;
}

int cedana_plugin_init(int stage)
{
	pr_info("cedana_plugin: started");
	return 0;
}

void cedana_plugin_fini(int stage, int ret)
{
	pr_info("cedana_plugin: finished");
}


CR_PLUGIN_REGISTER("cedanagpu_plugin", cedana_plugin_init, cedana_plugin_fini)

int cedana_plugin_handle_device_vma(int fd, const struct stat *st_buf)
{
	pr_info("cedana_plugin_handle_device_vma called");
	return 0;
}

CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__HANDLE_DEVICE_VMA, cedana_plugin_handle_device_vma)


int cedana_plugin_dump_file(int fd, int id)
{
	pr_info("cedana_plugin_dump_file called");
	return 0;
}

CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__DUMP_EXT_FILE, cedana_plugin_dump_file)


int cedana_plugin_restore_file(int id)
{
	pr_info("cedana_plugin_restore_file called");
	return 0;
}

CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESTORE_EXT_FILE, cedana_plugin_restore_file)

int cedana_plugin_update_vmamap(const char *in_path, const uint64_t addr, const uint64_t old_offset,
				uint64_t *new_offset, int *updated_fd)
{
	pr_info("cedana_plugin_update_vmamap called");
	return 0;
}

CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__UPDATE_VMA_MAP, cedana_plugin_update_vmamap)


int cedana_plugin_resume_devices_late(int pid)
{
	pr_info("cedana_plugin_resume_devices_late called");
	return 0;
}

CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESUME_DEVICES_LATE, cedana_plugin_resume_devices_late)
