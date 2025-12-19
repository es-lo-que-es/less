...
## INFO:
This fork contains a lesser version of Raysans rres. 

the only reason this fork exists -> 
i dont really like excessive re-llocations when u append / unpack data chunk props ._.   

i figure single data buffer is enough


### *MODIFICATIONS*

+ mod: removed all chunk types except CDIR and RAWD  
+ mod: removed encryption

+ mod: renamed all functions from rresName to lessName
+ mod: changed header magic bytes so i dont misstake this for original .rres

+ mod: added some functions to work with file pointers

---

+ mod: removed props since i only deal with raw data

``` C
typedef struct lessResourceChunkData {
    void *raw;                      // Resource chunk raw data
} lessResourceChunkData;
```

> central dir is now just data formatted as  
0-4:    dir count  
0-size: dir entries  
---

### *FIXES:*
+ fix: central dir offset actually absolute w/in the file
+ fix: version is 120 since last release was 1.2.0  

...
