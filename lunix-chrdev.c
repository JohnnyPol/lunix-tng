/*
 * lunix-chrdev.c
 *
 * Implementation of character devices
 * for Lunix:TNG
 *
 * Ioannis Polychronopoulos <el21089@mail.ntua.gr>
 * Kostas Stavliotis <>
 *
 */

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mmzone.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>

#include "lunix.h"
#include "lunix-chrdev.h"
#include "lunix-lookup.h"

/*
 * Global data
 */
struct cdev lunix_chrdev_cdev;

/*
 * Just a quick [unlocked] check to see if the cached
 * chrdev state needs to be updated from sensor measurements.
 */
/*
 * Declare a prototype so we can define the "unused" attribute and keep
 * the compiler happy. This function is not yet used, because this helpcode
 * is a stub.
 */
static int __attribute__((unused)) lunix_chrdev_state_needs_refresh(struct lunix_chrdev_state_struct *);
static int lunix_chrdev_state_needs_refresh(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct *sensor;
	
	WARN_ON ( !(sensor = state->sensor)); /* Logs a warning message in the kernel logs if the condition is true (non zero) */
	/*---------------------------OUR CODE----------------------------------------*/


    /* Compare the cached timestamp with the sensor's last update */
    if (sensor->msr_data[state->type]->last_update > state->buf_timestamp) {
        return 1; // Refresh needed
    }
    return 0; // No refresh needed
	
	/*---------------------------------------------------------------------------*/
}

/*
 * Updates the cached state of a character device
 * based on sensor data. Must be called with the
 * character device state lock held.
 */
static int lunix_chrdev_state_update(struct lunix_chrdev_state_struct *state)
{
	struct lunix_sensor_struct __attribute__((unused)) *sensor;
	/*---------------------------OUR CODE----------------------------------------*/

	struct lunix_msr_data_struct *msr_data;
	unsigned long flags; /* For spinlock */
    uint32_t raw_value, last_update;
    char formatted_data[LUNIX_CHRDEV_BUFSZ]; /* Buffer for formatted data */
    int formatted_len;
    long converted_value;
    long *lookup[N_LUNIX_MSR] = {lookup_voltage, lookup_temperature, lookup_light};

	/*---------------------------------------------------------------------------*/

	debug("entering\n"); /* Changed it to "entering" because it made a lot more sense */

	/*
	 * Grab the raw data quickly, hold the
	 * spinlock for as little as possible.
	 */
	/*---------------------------OUR CODE----------------------------------------*/

    /* Validate the sensor */
    sensor = state->sensor;
    WARN_ON(!(sensor = state->sensor)); 

	 /* Acquire the spinlock to safely access shared sensor data */
    spin_lock_irqsave(&sensor->lock, flags);

    /* Fetch the raw data */
    msr_data = sensor->msr_data[state->type];
	last_update = msr_data->last_update;
	raw_value = msr_data->values[0];

	/* Unlock */
    spin_unlock_irqrestore(&sensor->lock, flags);
	/*---------------------------------------------------------------------------*/

	/*
	 TODO: Why use spinlocks? See LDD3, p. 119
	 * Answer:  spinlocks protect sensor->msr_data because multiple threads or interrupts may access and modify the sensor data concurrently. 
	*/

	/*
	 * Any new data available?
	 */
	/*---------------------------OUR CODE----------------------------------------*/
	
	/* Check if the state needs a refresh */
    if (!lunix_chrdev_state_needs_refresh(state)) {
		debug("No new data available...\n");
        return -EAGAIN; // Error code that means "try again."
    }

	/*---------------------------------------------------------------------------*/


	/*
	 * Now we can take our time to format them,
	 * holding only the private state semaphore
	 */

	/*---------------------------OUR CODE----------------------------------------*/

	/* Update buffer timestamp */
    state->buf_timestamp = last_update;

    /* Convert and format data */
    converted_value = lookup[state->type][raw_value]; // Using the lookup table

	/* The converted value is in the form XXYYY while we want XX.YYY. For XX we get it from /1000 and the YYY from %1000 */
    formatted_len = snprintf(formatted_data, LUNIX_CHRDEV_BUFSZ, "%ld.%03ld\n",
                             converted_value / 1000, converted_value % 1000); 

    /* Check for buffer overflow */
    if (formatted_len >= LUNIX_CHRDEV_BUFSZ) {
        return -EOVERFLOW;
    }

    /* Update the state buffer */
    memcpy(state->buf_data, formatted_data, formatted_len); // Copy the data to the buffer.
    state->buf_lim = formatted_len;
	
	/*---------------------------------------------------------------------------*/


	debug("leaving\n");
	return 0;
}

/*************************************
 * Implementation of file operations
 * for the Lunix character device
 *************************************/

static int lunix_chrdev_open(struct inode *inode, struct file *filp)
{
	/* Declarations */
	/*---------------------------OUR CODE----------------------------------------*/
    int ret, minor, sensor_type, sensor_nb;
    struct lunix_chrdev_state_struct *p_state;

	debug("entering\n");
	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto out;

	/*
	 * Associate this open file with the relevant sensor based on
	 * the minor number of the device node [/dev/sensor<NO>-<TYPE>]
	 */

    minor = iminor(inode); 		/* Extracts the minor device number from the inode structure. */

	/* Calculations were figured out from the mk-lunix-devs.sh */
    sensor_nb = minor >> 3;  	/* Efficient bitwise calculation  (Division by 8)*/
    sensor_type = minor & 0x7; 	/* Same as "minor % 8" (Chose efficient bitwise calculation)*/

	if (sensor_type >= N_LUNIX_MSR) {
        ret = -ENODEV; // Means "No such device."
        goto out;
    }
	
	/* Allocate a new Lunix character device private state structure */

	p_state = kzalloc(sizeof(*p_state), GFP_KERNEL); 
	/* GFP_KERNEL specifies that the allocation is performed in the kernel's context and can sleep if memory isn’t immediately available.*/
    if (!p_state) {
        ret = -ENOMEM;
        printk(KERN_ERR "Failed to allocate memory for Lunix sensors\n");
        goto out;
    }

    p_state->type = sensor_type;
    p_state->sensor = &lunix_sensors[sensor_nb]; // ! see the structure of a state
    p_state->buf_timestamp = 0; // !  why 0
	/* This clears any residual data and ensures the buffer starts empty.*/
    memset(p_state->buf_data, 0, LUNIX_CHRDEV_BUFSZ); // memset initializes the buf_data buffer to zeros.
    p_state->buf_lim = 0;

	/* A semaphore is used to synchronize access to the p_state structure. */
    sema_init(&p_state->lock, 1); // 1 means we have mutex Lock
    filp->private_data = p_state; // filp is a pointer to the open file structure representing the file being accessed.

    ret = 0;
    debug("State of type %d and sensor %d successfully associated\n", sensor_type, sensor_nb);


	/*---------------------------------------------------------------------------*/
out:
	debug("leaving, with ret = %d\n", ret);
	return ret;
}

static int lunix_chrdev_release(struct inode *inode, struct file *filp)
{
	/*---------------------------OUR CODE----------------------------------------*/

	struct lunix_chrdev_state_struct *private_state;

    private_state = filp->private_data;
	// ! kfree and filp private_data?
    /* Clean up any resources associated with private_state if needed */
    kfree(private_state); // Free the allocated private state structure

    return 0;

	/*---------------------------------------------------------------------------*/
}

static long lunix_chrdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	return -EINVAL;
}

static ssize_t lunix_chrdev_read(struct file *filp, char __user *usrbuf, size_t cnt, loff_t *f_pos)
{
	ssize_t ret;

	struct lunix_sensor_struct *sensor;
	struct lunix_chrdev_state_struct *state;

	state = filp->private_data;
	WARN_ON(!(state); // ! what is warn_on

	sensor = state->sensor;
	WARN_ON(!sensor);

	
	/*---------------------------OUR CODE----------------------------------------*/
	if (down_interruptible(&state->lock)) { // ! what is down_interruptible
        return -ERESTARTSYS;
    }
	
	/*
	 * If the cached character device state needs to be
	 * updated by actual sensor data (i.e. we need to report
	 * on a "fresh" measurement, do so
	 */
	if (*f_pos == 0) {
		while (lunix_chrdev_state_update(state) == -EAGAIN) {
			/* The process needs to sleep 
			TODO: See LDD3, page 153 for a hint 
			*/
			up(&state->lock); // ! why up
			if (filp->f_flags & O_NONBLOCK) {
                return -EAGAIN;
            }
            debug("\"%s\" reading: going to sleep\n", current->comm); /* Name of the current process */
            if (wait_event_interruptible(sensor->wq, lunix_chrdev_state_needs_refresh(state))) {
                return -ERESTARTSYS;
            }
            if (down_interruptible(&state->lock)) {
                return -ERESTARTSYS;
            }
		}
	}
	/*---------------------------------------------------------------------------*/

	/* End of file */
	/*---------------------------OUR CODE----------------------------------------*/

	if (state->buf_lim == 0) { // Nothing to read, EOF reached 
        ret = 0;
        goto out;
    }

	/*---------------------------------------------------------------------------*/
	
	/* Determine the number of cached bytes to copy to userspace */
	/*---------------------------OUR CODE----------------------------------------*/

	if (cnt > state->buf_lim - *f_pos) { // ! how does this calculation work?
        cnt = state->buf_lim - *f_pos;
    }

	/* Copy data to user space */
    if (copy_to_user(usrbuf, state->buf_data + *f_pos, cnt)) {  // ! what does this function do?
        ret = -EFAULT; // ! error
        goto out;
    }
	debug("We read %zu bytes of data\n", cnt); // ! what is %zu?

	/* Update file position */
    *f_pos += cnt;
    ret = cnt;

	/*---------------------------------------------------------------------------*/

	/* Auto-rewind on EOF mode? */
	/*---------------------------OUR CODE----------------------------------------*/

    if (*f_pos >= state->buf_lim) { // ! explain
        *f_pos = 0;
    }

	/*---------------------------------------------------------------------------*/
out:
	/* Unlock */
	up(&state->lock); // ! why?
	return ret;
}

static int lunix_chrdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	return -EINVAL;
}

static struct file_operations lunix_chrdev_fops = 
{
	.owner          = THIS_MODULE,
	.open           = lunix_chrdev_open,
	.release        = lunix_chrdev_release,
	.read           = lunix_chrdev_read,
	.unlocked_ioctl = lunix_chrdev_ioctl,
	.mmap           = lunix_chrdev_mmap
};

int lunix_chrdev_init(void)
{
	/*
	 * Register the character device with the kernel, asking for
	 * a range of minor numbers (number of sensors * 8 measurements / sensor)
	 * beginning with LINUX_CHRDEV_MAJOR:0
	 */
	int ret;
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;

	debug("initializing character device\n");
	cdev_init(&lunix_chrdev_cdev, &lunix_chrdev_fops);
	lunix_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	/* register_chrdev_region? */

	/*---------------------------OUR CODE----------------------------------------*/
	// Register the character device region (allocate major and minor numbers)
	ret = register_chrdev_region(dev_no, lunix_minor_cnt, "lunix_chrdev"); // ! what does  this function do?
	/*---------------------------------------------------------------------------*/

	if (ret < 0) {
		debug("failed to register region, ret = %d\n", ret);
		goto out;
	}

	/* cdev_add */
	/*---------------------------OUR CODE----------------------------------------*/
	ret = cdev_add(&lunix_chrdev_cdev, dev_no, lunix_minor_cnt); // ! what does this function do?
	/*---------------------------------------------------------------------------*/
	if (ret < 0) {
		debug("failed to add character device\n");
		goto out_with_chrdev_region;
	}
	debug("completed successfully\n");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
out:
	return ret;
}

void lunix_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;

	debug("entering\n");
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	cdev_del(&lunix_chrdev_cdev);
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
	debug("leaving\n");
}
