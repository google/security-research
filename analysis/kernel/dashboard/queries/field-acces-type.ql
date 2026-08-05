import cpp

abstract class InterestingFieldAccesses extends FieldAccess {
    InterestingFieldAccesses() {
        any()
    }

    string accessType() { result = ""}
}

class FieldExec extends InterestingFieldAccesses {
    FieldExec() { exists(ExprCall ec | ec.getExpr() = this)}

    override string accessType() {result = "exec"}
}


class FieldWrite extends InterestingFieldAccesses {
    FieldWrite() { this.isModified()}

    override string accessType() {result = "write"}
}

class FieldRead extends InterestingFieldAccesses {
    FieldRead() { this.isRValue() }

    override string accessType() {result = "read"}
}


from InterestingFieldAccesses ifa
select ifa.accessType(), ifa.getTarget(), ifa.getTarget().getDeclaringType(), ifa.getLocation()