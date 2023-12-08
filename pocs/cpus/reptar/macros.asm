
; macro to generate rex bytes
; e.g. rex w,x,b
%macro rex 0-4
    %assign _rex 0b01000000
    %rep %0
        %ifidni   %1, W
         %assign _rex _rex | 0b1000
        %elifidni %1, R
         %assign _rex _rex | 0b0100
        %elifidni %1, X
         %assign _rex _rex | 0b0010
        %elifidni %1, B
         %assign _rex _rex | 0b0001
        %else
         %error unrecognized flag %1
        %endif
        %rotate 1
    %endrep
    db _rex
%endmacro
