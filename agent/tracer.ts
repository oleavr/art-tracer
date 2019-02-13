import { getApi } from "frida-java/lib/android";
import { log } from "./logger";
import { prototype } from "stream";
const api = getApi();

export interface TraceCallbacks {
    onEnter(methodName: string): void;
    onLeave(methodName: string): void;
}

enum InstrumentationEvent {
    MethodEntered = 0x1,
    MethodExited = 0x2,
    MethodUnwind = 0x4,
    DexPcMoved = 0x8,
    FieldRead = 0x10,
    FieldWritten = 0x20,
    ExceptionCaught = 0x40,
    Branch = 0x80,
    InvokeVirtualOrInterface = 0x100,
}

const retainedHandles: any[] = [];  // to keep calbacks alive

let listener: NativePointer;
try {
    listener = makeListener();
} catch (e) {
    log("Shit: " + e.stack);
}

const getUtfLength: any = new NativeFunction(
    Module.findExportByName("libart.so","_ZN3art6mirror6String12GetUtfLengthEv") as NativePointer,
    "int32",
    ["pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
const toCharArray: any = new NativeFunction(
    Module.findExportByName("libart.so","_ZN3art6mirror6String11ToCharArrayEPNS_6ThreadE") as NativePointer,
    "pointer",
    ["pointer","pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
const getData: any = new NativeFunction(
    Module.findExportByName("libart.so","_ZNK3art6mirror14PrimitiveArrayItE7GetDataEv") as NativePointer,
    "pointer",
    ["pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
const operatorDelete: any = new NativeFunction(
    Module.findExportByName("libc++.so","_ZdlPv") as NativePointer,
    "void",
    ["pointer"],
    {
        exceptions: ExceptionsBehavior.Propagate
    });
    


    
export function trace(callbacks: TraceCallbacks) {
    log("trace() starting up");

    const runtime = api.artRuntime;
    const instrumentationOffset = 488;
    const instrumentation = runtime.add(instrumentationOffset);

    const helperPath = "/data/local/tmp/re.frida.server/libart-tracer-helper.so";
    const dlopen: any = new NativeFunction(Module.findExportByName(null, "dlopen") as NativePointer, "pointer", ["pointer", "int"]);
    const helper = dlopen(Memory.allocUtf8String(helperPath), 3);
    if (!helper.isNull()) {
        const getOffsetOfRuntimeInstrumentation: any = new NativeFunction(Module.findExportByName(helperPath, "ath_get_offset_of_runtime_instrumentation") as NativePointer, "uint", []);
        log("we think instrumentation is at offset " + instrumentationOffset + ", helper thinks it's at " + getOffsetOfRuntimeInstrumentation());
    } else {
        const dlerror: any = new NativeFunction(Module.findExportByName(null, "dlerror") as NativePointer, "pointer", []);
        log("failed to load helper: " + Memory.readUtf8String(dlerror()));
    }

    const addListener: any = new NativeFunction(
        Module.findExportByName("libart.so","_ZN3art15instrumentation15Instrumentation11AddListenerEPNS0_23InstrumentationListenerEj") as NativePointer,
        "void",
        ["pointer","pointer","uint32"],
        {
            exceptions: ExceptionsBehavior.Propagate
        });
    const enableDeoptimization: any = new NativeFunction(
        Module.findExportByName("libart.so","_ZN3art15instrumentation15Instrumentation20EnableDeoptimizationEv") as NativePointer,
        "void",
        ["pointer"],
        {
            exceptions: ExceptionsBehavior.Propagate
        });
    const deoptimizeEverything: any = new NativeFunction(
        Module.findExportByName("libart.so","_ZN3art15instrumentation15Instrumentation20DeoptimizeEverythingEPKc") as NativePointer,
        "void",
        ["pointer","pointer"],
        {
            exceptions: ExceptionsBehavior.Propagate
        });
      
    enableDeoptimization(instrumentation);
    deoptimizeEverything(instrumentation, Memory.allocUtf8String("frida"));
    addListener(instrumentation, listener, InstrumentationEvent.MethodEntered /* | InstrumentationEvent.MethodExited | InstrumentationEvent.FieldRead | InstrumentationEvent.FieldWritten*/);
    log("--------> after api: " + JSON.stringify(api));    
}

function makeListener(): NativePointer {
    const numVirtuals = 11;

    const listener = Memory.alloc(Process.pointerSize);
    retainedHandles.push(listener);

    const vtable = Memory.alloc(numVirtuals * Process.pointerSize);
    retainedHandles.push(vtable);
    Memory.writePointer(listener, vtable);

    for (let i = 0; i !== numVirtuals; i++) {
        switch(i) { 
            case 2: { 
                const method = makeMethodEntered();
                Memory.writePointer(vtable.add(i * Process.pointerSize), method);
                break; 
            } 
            case 3: { 
                const method = makeMethodExited();
                Memory.writePointer(vtable.add(i * Process.pointerSize), method);
                break; 
            } 
            case 6: { 
                const method = makeFieldRead();
                Memory.writePointer(vtable.add(i * Process.pointerSize), method);
                break; 
            } 
            case 7: { 
                const method = makeFieldWritten();
                Memory.writePointer(vtable.add(i * Process.pointerSize), method);
                break; 
            }
            default: { 
                const method = makeListenerMethod("vmethod" + i);
                Memory.writePointer(vtable.add(i * Process.pointerSize), method);
                break; 
            } 
        } 
    }
    return listener;
}

function getNameFromStringObject(stringObject:NativePointer, thread: NativePointer):string|null{
    let length = getUtfLength(stringObject);
    let charArray = toCharArray(stringObject,thread);
    let datas = getData(charArray);     
    return Memory.readUtf16String(datas,length);
} 

function makeMethodEntered(): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer, thisObject: NativePointer, method: NativePointer, dexPc: number): void => {
        
        const getNameAsString: any = new NativeFunction(
            Module.findExportByName("libart.so","_ZN3art9ArtMethod15GetNameAsStringEPNS_6ThreadE") as NativePointer,
            "pointer",
            ["pointer","pointer"],
            {
                exceptions: ExceptionsBehavior.Propagate
            });
        let methodNameStringObject = getNameAsString(method, thread); 
        const stringMethodName = getNameFromStringObject(methodNameStringObject,thread);

        /// GETTING THE CLASS NAME : APPROACH BY METHOD CLASS 
        let declaringClassOffset = 0;
        const declaring_classHandle= method.add(declaringClassOffset);
        const declaring_class_ = ptr(Memory.readU32(declaring_classHandle));

        /// TRYING WITH THE DESCRIPTOR    const char* Class::GetDescriptor(std::string* storage)
        const getDescriptor: any = new NativeFunction(
            Module.findExportByName("libart.so","_ZN3art6mirror5Class13GetDescriptorEPNSt3__112basic_stringIcNS2_11char_traitsIcEENS2_9allocatorIcEEEE") as NativePointer,
            "pointer",
            ["pointer","pointer"],
            {
                exceptions: ExceptionsBehavior.Propagate
            });

        let rawClassName: string;
        const storage = new StdString();
        rawClassName = Memory.readUtf8String(getDescriptor(declaring_class_, storage)) as string;   
        storage.dispose();

        const className = rawClassName.substring(1, rawClassName.length - 1).replace(/\//g, ".");
        log("///////**start**///////")
        log("MethodEntered() thisObject=" + thisObject + " method=" + method + " descriptor=" + className + " dex_pc=" + dexPc);
        //just test the method
        if(!method.isNull()) log("-/testing this method : " +  Memory.readU32(method.add(8)));
        // NOW GETTING THE ARGUMENTS
       
        // I will use the managed stack (offset 140 of the thread Object)
        let managed_stack  = thread.add(140);
        log("---Managed stack=" + managed_stack);

        // try to access the shadow stack (it is private but we don't care??? Ole answer)
        let shadow_frame_from_managed_stack = Memory.readPointer(managed_stack.add(2 * Process.pointerSize));
        log("-Shadow frame from managed stack =" + shadow_frame_from_managed_stack);
        let art_method_0 = shadow_frame_from_managed_stack.isNull() ? new NativePointer(0) : Memory.readPointer(shadow_frame_from_managed_stack.add(1*Process.pointerSize));
        log("-corresponding method =" + art_method_0);
         //just to test offset
        let dex_pc_ptr_val_managed_stack= shadow_frame_from_managed_stack.isNull() ? null : Memory.readU32(shadow_frame_from_managed_stack.add(4*Process.pointerSize));
        log("dex_pc =" + dex_pc_ptr_val_managed_stack);
        //just test the method
        if(!art_method_0.isNull()) log("-/testing this method : (dex_method_index_) " +  Memory.readU32(art_method_0.add(8)));
        
        let top_quick_frame_add = Memory.readPointer(managed_stack);  
        log("-Top quick frame from managed stack =" + top_quick_frame_add);
        let art_method_1 = top_quick_frame_add.isNull() ? new NativePointer(0) : Memory.readPointer(top_quick_frame_add);
        log("-Corresponding method : " + art_method_1); /// because the quick frame contains pointer to methods. 
        //just test the method
        if(!art_method_1.isNull()) log("-/testing this method : (dex_method_index_) " +  Memory.readU32(art_method_1.add(8)));
      

        // We can also use the instrumentation stack *
        let instrumentation_stack = Memory.readPointer(thread.add(208));
        log("-Instrumentation stack handle=" + instrumentation_stack);
        let instrumentationStack : StdInstrumentationStackDeque = new StdInstrumentationStackDeque(instrumentation_stack);
    
        let front_frame = instrumentationStack.front();
        log("-----front frame of the instrumentation stack = " + front_frame);
        let art_method_front =  front_frame.isNull() ? new NativePointer(0) : Memory.readPointer(front_frame.add(1 * Process.pointerSize));
        log("-Corresponding method : " + art_method_front);
        //just to test offset
        let interpreter_entry_front= front_frame.isNull() ? null : Memory.readInt(front_frame.add(16));
        log("interpreter_entry_ =" + interpreter_entry_front);
        //just test the method
        if(!art_method_front.isNull()) log("-/testing this method : (dex_method_index_)" +  Memory.readU32(art_method_front.add(8)));


        let back_frame = instrumentationStack.back();
        log("-----back frame of the instrumentation stack = " + back_frame);
        let art_method_back =  back_frame.isNull() ? new NativePointer(0) : Memory.readPointer(back_frame.add(1 * Process.pointerSize));
        log("-Corresponding method : " + art_method_back);
        //just to test offset
        let interpreter_entry_back= back_frame.isNull() ? null : Memory.readInt(back_frame.add(16));
        log("interpreter_entry_ =" + interpreter_entry_back);
        //just test the method
        if(!art_method_back.isNull()) log("-/testing this method : (dex_method_index_)" +  Memory.readU32(art_method_back.add(8)));




        
    }, "void", ["pointer", "pointer", "pointer", "pointer", "uint32"]);
    retainedHandles.push(callback);

    return callback;
}
function makeMethodExited(): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer, thisObject: NativePointer, method: NativePointer, dexPc: number, returnValue: NativePointer): void => {
        log("MethodExited() thisObject=" + thisObject + " method=" + method + " JValue=" + returnValue);
    }, "void", ["pointer", "pointer", "pointer", "pointer", "uint32","pointer"]);
    retainedHandles.push(callback);
    return callback;
}

function makeListenerMethod(name: string): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer): void => {
        log(name + " was called!");
    }, "void", ["pointer", "pointer"]);
    retainedHandles.push(callback);

    return callback;
}

function makeFieldRead(): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer, thisObject: NativePointer, method: NativePointer, dexPc: number, field: NativePointer): void => {
        log("FieldRead() thisObject=" + thisObject + " method=" + method+ " fieldObject="+field);
    }, "void", ["pointer", "pointer", "pointer", "pointer", "uint32","pointer"]);
    retainedHandles.push(callback);

    return callback;
}

function makeFieldWritten(): NativePointer {
    const callback = new NativeCallback((self: NativePointer, thread: NativePointer, thisObject: NativePointer, method: NativePointer, dexPc: number, field: NativePointer, field_value: NativePointer): void => {
        log("FieldWritten() thisObject=" + thisObject + " method=" + method);
    }, "void", ["pointer", "pointer", "pointer", "pointer", "uint32","pointer","pointer"]);
    retainedHandles.push(callback);

    return callback;
}

class StdString {
    handle: NativePointer;

    constructor() {    
        this.handle = Memory.alloc(3 * Process.pointerSize);
    }

    dispose(): void {
        if (!this.isTiny()) {
            operatorDelete(this.getAllocatedBuffer());
        }
    }

    read(): string {
        //log(hexdump(this.handle, { length: 12 }));
        let str: string | null = null;
        if (this.isTiny()) {
            str = Memory.readUtf8String(this.handle.add(1));  ///////////////////////////  1*Process.pointerSize
        } else {
            str = Memory.readUtf8String(this.getAllocatedBuffer());
        }
        return (str !== null) ? str : "";
    }
    
    private isTiny(): boolean {
        return (Memory.readU8(this.handle) & 1) === 0;
    }

    private getAllocatedBuffer(): NativePointer {
        return Memory.readPointer(this.handle.add(2 * Process.pointerSize));
    }
}

class StdInstrumentationStackDeque {
    // from the class definition https://github.com/llvm-mirror/libcxx/blob/master/include/deque
    // line 959 you have three parameters 
    // to simplify we remove the private inerhitrance with deque_base
    handle: NativePointer;
    __start_ : number = 0;
    //__block_size is a const (line 945). Initialized (line 1037)
    // in the __deque_block_size struct value_type size is 20 and 
    // refferring to the line  276 it is < 256 , so we have 4096/20 =~ 204
    __block_size : number = 204; 
    constructor(handle_: NativePointer) {
        log(" we construct the stack object"); 
        let __start_Offset  = 4*Process.pointerSize; 
        this.handle = handle_;
        this.__start_ = Memory.readUInt(handle_.add(__start_Offset));
        
    }

    // actualize other attributes at every read

    size(): number {
        // it is in the third parameter, first element of the compressed pair  https://www.boost.org/doc/libs/1_47_0/boost/detail/compressed_pair.hpp  
        let sizeOffset = 5*Process.pointerSize;
        let result = Memory.readUInt(this.handle.add(sizeOffset));  
        log ("- size of the instrumentation queue : " + result);
        return result;
    }

    __map_begin(): NativePointer {
        // it is in  the first parameter __map_,   witch is a split_buffer 
        // https://github.com/google/libcxx/blob/master/include/__split_buffer line 47  
        let sizeOffset = 1*Process.pointerSize;
        let result = Memory.readPointer(this.handle.add(sizeOffset)); 
        log ("- begin of the  map in instrumentation queue : " + result); 
        return result;
    }

    __map_end(): NativePointer {
        // it is in  the first parameter __map_,   witch is a split_buffer 
        // https://github.com/google/libcxx/blob/master/include/__split_buffer line 48 
        let endOffset = 2*Process.pointerSize;
        let result = Memory.readPointer(this.handle.add(endOffset));  
        log ("- end of the map of the instrumentation queue : " + result);
        return result;
    }
    __map_empty(): boolean {
        // it is compute from   the first parameter  __map_, witch is a split_buffer 
        // https://github.com/google/libcxx/blob/master/include/__split_buffer line 85
        let result =  this.__map_end().compare(this.__map_begin()) == 0;
        log ("- map  of the instrumentation queue  is empty: " + result);
        return result;
    }
    
    refresh(){
        let __start_Offset  = 4*Process.pointerSize; 
        this.__start_ = Memory.readUInt(this.handle.add(__start_Offset));
        log ("- start offset in the map of the instrumentation queue : " + this.__start_);
    }
    front(): NativePointer {
        // here we don't dereference the result, it is still a pointer 
        // defined at line 1788 https://github.com/llvm-mirror/libcxx/blob/master/include/deque
        this.refresh();
        log("---  we get the front of the deque"); 
        let __p : number =  this.__start_;
        log(" value of p " + __p); 
        let  __mp : NativePointer = this.__map_begin().add(Math.floor(__p / this.__block_size) * Process.pointerSize) ;
        log (" processing the __mp : " + __mp + " with ratio p/size : " +  Math.floor(__p / this.__block_size)
                                 + " p%size = " + __p % this.__block_size);
        let result : NativePointer = Memory.readPointer(__mp).add((__p % this.__block_size) * Process.pointerSize);
        log("final result " + result );
        return result;
    } 

    back(): NativePointer {
        // here we don't dereference the result, it is still a pointer 
        // defined at line 1815 https://github.com/llvm-mirror/libcxx/blob/master/include/deque
        this.refresh();
        log("---  we get the front of the deque"); 
        let __p : number =  this.size() + this.__start_ - 1;
        log(" value of p " + __p); 
        let  __mp : NativePointer = this.__map_begin().add(Math.floor(__p / this.__block_size) * Process.pointerSize) ;
        log (" processing the __mp : " + __mp + " with ratio p/size : " +  Math.floor(__p / this.__block_size)
                                 + " p%size = " + __p % this.__block_size);
        let result : NativePointer = Memory.readPointer(__mp).add((__p % this.__block_size) * Process.pointerSize);
        log("final result " + result );
        return result;
    } 

    /* end(): NativePointer {
    // defined at line 1086 https://github.com/llvm-mirror/libcxx/blob/master/include/deque
    // we ignore the iterator 
    // supposing that the second arg of __mp it contains the address of the element we want 
    // (it second is the one retrived when referencing the iterator at line 318)
    this.refresh();
    log("---  we get the end"); 
    let __p : number = this.size() + this.__start_;
    log(" value of p " + __p); 
    let  __mp : NativePointer = this.__map_begin().add(  Math.floor(__p / this.__block_size)) ;
    log (" processing the __mp : " + __mp + " with ratio p/size : " +  Math.floor(__p / this.__block_size)
                                + " p%size = " + __p % this.__block_size);
    let result : NativePointer = this.__map_empty() ? 
                                    new NativePointer(0) :
                                    Memory.readPointer(__mp).add((__p % this.__block_size));
    log("final result " + result );
    return result;
    }*/


}