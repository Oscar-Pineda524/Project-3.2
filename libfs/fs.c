#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "disk.h"
#include "fs.h"

#define FS_SIG "ECS150FS"
#define FS_SIG_LEN 8
#define FAT_EOC 0xFFFF
#define FD_MAX_COUNT 32

struct file_descriptor {
    int used;                     // is this entry used?
    struct root_entry *file;     // pointer to the root directory entry
    size_t offset;               // current file offset
};

static struct file_descriptor fd_table[FD_MAX_COUNT];


struct __attribute__((packed)) superblock {
    char signature[8];             // 0x00
    uint16_t total_blk_count;      // 0x08
    uint16_t rdir_blk;             // 0x0A
    uint16_t data_blk;             // 0x0C
    uint16_t data_count;           // 0x0E
    uint8_t fat_blk_count;         // 0x10
    uint8_t unused[BLOCK_SIZE - 16]; // 0x11
};

// Root directory entry
struct __attribute__((packed)) root_entry {
    char filename[FS_FILENAME_LEN];   // 0x00
    uint32_t size;                    // 0x10
    uint16_t first_data_index;        // 0x14
    uint8_t unused[10];               // 0x16
};

static struct superblock sb;
static uint16_t *fat = NULL;
static struct root_entry root_dir[FS_FILE_MAX_COUNT];
static int fs_mounted = 0;

int fs_mount(const char *diskname)
{
	    if (fs_mounted)
        return -1;

    if (block_disk_open(diskname) < 0)
        return -1;

    if (block_read(0, &sb) < 0)
        return -1;

    if (strncmp(sb.signature, FS_SIG, FS_SIG_LEN) != 0)
        return -1;

    if (sb.total_blk_count != block_disk_count())
        return -1;

    fat = malloc(sb.fat_blk_count * BLOCK_SIZE);
    if (!fat)
        return -1;

    for (int i = 0; i < sb.fat_blk_count; i++) {
        if (block_read(1 + i, (uint8_t*)fat + i * BLOCK_SIZE) < 0)
            return -1;
    }

    if (block_read(sb.rdir_blk, root_dir) < 0)
        return -1;

    fs_mounted = 1;
    return 0;
}

int fs_umount(void)
{
	    if (!fs_mounted)
        return -1;

    if (block_write(sb.rdir_blk, root_dir) < 0)
        return -1;

    for (int i = 0; i < sb.fat_blk_count; i++) {
        if (block_write(1 + i, (uint8_t*)fat + i * BLOCK_SIZE) < 0)
            return -1;
    }

    free(fat);
    fat = NULL;
    fs_mounted = 0;

    return block_disk_close();
}

int fs_info(void)
{
	   if (!fs_mounted)
        return -1;

    printf("FS Info:\n");
    printf("total_blk_count=%d\n", sb.total_blk_count);
    printf("fat_blk_count=%d\n", sb.fat_blk_count);
    printf("rdir_blk=%d\n", sb.rdir_blk);
    printf("data_blk=%d\n", sb.data_blk);
    printf("data_blk_count=%d\n", sb.data_count);

    int fat_used = 0;
    for (int i = 0; i < sb.data_count; i++) {
        if (fat[i] != 0) {
            fat_used++;
        }
    }
    int fat_free = sb.data_count - fat_used;
    printf("fat_free_ratio=%d/%d\n", fat_free, sb.data_count);

    int root_used = 0;
    for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if (root_dir[i].filename[0] != '\0') {
            root_used++;
        }
    }
    int root_free = FS_FILE_MAX_COUNT - root_used;
    printf("rdir_free_ratio=%d/%d\n", root_free, FS_FILE_MAX_COUNT);

    return 0;
}

int fs_create(const char *filename)
{
	/* TODO: Phase 2 */

    //error check
    if (!fs_mounted || filename == NULL || strlen(filename) == 0 || strlen(filename) >= FS_FILENAME_LEN ) {
        return -1;
    }

    //check for already existing file
    for(int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if(strncmp(root_dir[i].filename, filename, FS_FILENAME_LEN) == 0)
        return -1;
    }

    //finds empty entry in root directory and fills it out
    for(int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if (root_dir[i].filename[0] == '\0') {
            strncpy(root_dir[i].filename, filename, FS_FILENAME_LEN);
            root_dir[i].filename[FS_FILENAME_LEN - 1] = '\0'; 
            root_dir[i].size = 0;
            root_dir[i].first_data_index = FAT_EOC;

            if (block_write(sb.rdir_blk, root_dir) < 0){
                return -1;
            }

            return 0;
        }
    }

    return -1;
}

int fs_delete(const char *filename)
{
	/* TODO: Phase 2 */
    if (!fs_mounted || filename == NULL || strlen(filename) == 0 || strlen(filename) >= FS_FILENAME_LEN) {
        return -1;
    }

    for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if (strncmp(root_dir[i].filename, filename, FS_FILENAME_LEN) == 0) {
            uint16_t curr = root_dir[i].first_data_index;

            //frees the FAT chain
            while (curr != FAT_EOC) {
                uint16_t next = fat[curr];
                fat[curr] = 0;
                curr = next; 
            }

            //Clears the root entry
            memset(&root_dir[i], 0, sizeof(struct root_entry));

            for(int j = 0; j < sb.fat_blk_count; j++) {
                if (block_write(1 + j, (uint8_t*)fat + j * BLOCK_SIZE) < 0){
                    return -1;
                }                
            }
            if (block_write(sb.rdir_blk, root_dir) < 0) {
                return -1;
            }

            return 0;
        }
    }

    return -1;
}

int fs_ls(void)
{
	/* TODO: Phase 2 */

    if (!fs_mounted){
        return -1;
    }

    for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if(root_dir[i].filename[0] != '\0') {
            printf("file: %s, size: %u, data_blk: %u\n", //check reference program for formatting
                   root_dir[i].filename,
                   root_dir[i].size,
                   root_dir[i].first_data_index);
        }
    }

    return 0;
}

int fs_open(const char *filename)
{
	/* TODO: Phase 3 */
	if (!fs_mounted || filename == NULL)
        return -1;

    //finds the file in the root directory
    struct root_entry *entry = NULL;
    for (int i = 0; i < FS_FILE_MAX_COUNT; i++) {
        if (strncmp(root_dir[i].filename, filename, FS_FILENAME_LEN) == 0) {
            entry = &root_dir[i];
            break;
        }
    }

    if (!entry) return -1; //file not found

    //finding unused slot in fd_table
    for (int fd = 0; fd < FD_MAX_COUNT; fd++) {
        if (!fd_table[fd].used) {
            fd_table[fd].used = 1;
            fd_table[fd].file = entry;
            fd_table[fd].offset = 0;
            return fd;
        }
    }

    return -1; //no free fd's
}

int fs_close(int fd)
{
	/* TODO: Phase 3 */
	if (!fs_mounted || fd < 0 || fd >= FD_MAX_COUNT || !fd_table[fd].used)
        return -1;

    fd_table[fd].used = 0;
    fd_table[fd].file = NULL;
    fd_table[fd].offset = 0;
    return 0;
}

int fs_stat(int fd)
{
	/* TODO: Phase 3 */
	if (!fs_mounted || fd < 0 || fd >= FD_MAX_COUNT || !fd_table[fd].used)
        return -1;

    return fd_table[fd].file->size;
}

int fs_lseek(int fd, size_t offset)
{
	/* TODO: Phase 3 */
	if (!fs_mounted || fd < 0 || fd >= FD_MAX_COUNT || !fd_table[fd].used)
        return -1;

    if (offset > fd_table[fd].file->size)
        return -1;

    fd_table[fd].offset = offset;
    return 0;
}

static int allocate_free_block()
{
    for (int i = 0; i < sb.data_count; i++) {
        if (fat[i] == 0) {
            fat[i] = FAT_EOC;  // Mark as allocated
            return i;
        }
    }
    return -1;  // No free block found
}

static int get_block_index_or_allocate(struct root_entry *file, size_t offset)
{
    uint16_t block_index = file->first_data_index;

    // If the file is empty, allocate the first block
    if (block_index == FAT_EOC) {
        int new_block = allocate_free_block();
        if (new_block < 0) {
            return -1;
        }
        file->first_data_index = new_block;
        return new_block;
    }

    // Traverse the FAT chain
    size_t block_pos = offset / BLOCK_SIZE;
    for (size_t i = 0; i < block_pos; i++) {
        if (fat[block_index] == FAT_EOC) {
            // Allocate a new block and link it
            int new_block = allocate_free_block();
            if (new_block < 0) {
                return -1;
            }
            fat[block_index] = new_block;
            fat[new_block] = FAT_EOC;
        }
        block_index = fat[block_index];
    }

    return block_index;
}

int fs_write(int fd, void *buf, size_t count)
{
	/* TODO: Phase 4 */

    if (!fs_mounted || fd < 0 || fd >= FD_MAX_COUNT || !fd_table[fd].used){
        return -1;
    }

    struct file_descriptor *fd_entry = &fd_table[fd];
    struct root_entry *file = fd_entry->file;

    size_t offset = fd_entry->offset;
    size_t bytes_written = 0;
    uint8_t bounce_buffer[BLOCK_SIZE];

    while (bytes_written < count){
        int block_index = get_block_index_or_allocate(file, offset);
        if (block_index < 0) {
            return -1;
        }

        if (block_read(sb.data_blk + block_index, bounce_buffer) < 0) {
            return -1;
        }

        size_t offset_in_block = offset % BLOCK_SIZE;
        size_t space_in_block = BLOCK_SIZE - offset_in_block;
        size_t copy_bytes = (count - bytes_written < space_in_block) ? (count - bytes_written) : space_in_block;
        
        memcpy(bounce_buffer + offset_in_block, (uint8_t*)buf + bytes_written, copy_bytes);

        // Write the modified block back to disk
        if (block_write(sb.data_blk + block_index, bounce_buffer) < 0) {
            return -1;
        }

        offset += copy_bytes;
        bytes_written += copy_bytes;
    }

    fd_entry->offset = offset;
    if (offset > file->size) {
        file->size = offset;
    }

    // Write back FAT to disk
    for (int i = 0; i < sb.fat_blk_count; i++) {
        if (block_write(1 + i, (uint8_t*)fat + i * BLOCK_SIZE) < 0) {
            return -1;
        }
    }

    // Write back root directory to disk
    if (block_write(sb.rdir_blk, root_dir) < 0) {
        return -1;
    }

    return bytes_written;

}

int fs_read(int fd, void *buf, size_t count)
{
	/* TODO: Phase 4 */
    if (!fs_mounted || fd < 0 || fd >= FD_MAX_COUNT || !fd_table[fd].used)
        return -1;
    
    struct file_descriptor *fd_entry = &fd_table[fd];
    struct root_entry *file = fd_entry->file;

    size_t offset = fd_entry->offset;
    size_t file_size = file->size;

    if (offset >= file_size) {
        return 0;
    }

    size_t bytes_to_read = count;
    if (offset + bytes_to_read > file_size) {
        bytes_to_read = file_size - offset; 
    }

    size_t bytes_read = 0;
    uint8_t bounce_buffer[BLOCK_SIZE];

    uint16_t block_index = file->first_data_index;
    size_t block_offset = offset;
    while (block_offset >= BLOCK_SIZE && block_index != FAT_EOC){
        block_index = fat[block_index];
        block_offset -= BLOCK_SIZE; 
    }

    while (bytes_read < bytes_to_read && block_index != FAT_EOC) {
        if(block_read(sb.data_blk + block_index, bounce_buffer) < 0){
            return -1;
        }

        size_t offset_in_block = block_offset % BLOCK_SIZE;
        size_t space_in_block = BLOCK_SIZE - offset_in_block;
        size_t copy_bytes = (bytes_to_read - bytes_read < space_in_block) ? (bytes_to_read - bytes_read) : space_in_block;

        memcpy((uint8_t*)buf + bytes_read, bounce_buffer + offset_in_block, copy_bytes);

        bytes_read += copy_bytes;
        block_offset = 0;

        block_index = fat[block_index];
    }

    fd_entry->offset += bytes_read;

    return bytes_read;

}
