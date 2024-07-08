const sendit = () => {
    const username = document.regiform.username;
    const userid = document.regiform.userid;
	const userpw = document.regiform.userpw;
    const userpw_ch = document.regiform.userpw_ch;
    const Email = document.regiform.useremail;
    
    // username
    if(username.value == '') {
        alert('이름을 입력해주세요.');
        username.focus();
        return false;
    }

    // userid
    if(userid.value == '') {
        alert('아이디를 입력해주세요.');
        userid.focus();
        return false;
    }

    if(userid.value.length < 4 || userid.value.length > 12){
        alert("아이디는 4자 이상 12자 이하로 입력해주세요.");
        userid.focus();
        return false;
    }

    // userpw
    if(userpw.value == '') {
        alert('비밀번호를 입력해주세요.');
        userpw.focus();
        return false;
    }

    if(!/^[a-zA-Z0-9!@#$%^&*()?_~]{6,15}$/.test(userpw.value)){
        alert("비밀번호는 숫자, 영문, 특수문자 조합으로 6~15자리를 사용해야 합니다.");
        userpw.focus();
        return false;
    }
    
    // 영문, 숫자, 특수문자 2종 이상 혼용
    var chk = 0;
    if(userpw.value.search(/[0-9]/g) != -1 ) chk ++;
    if(userpw.value.search(/[a-z]/ig)  != -1 ) chk ++;
    if(userpw.value.search(/[!@#$%^&*()?_~]/g)  != -1  ) chk ++;
    if(chk < 2)
    {
        alert("비밀번호는 숫자, 영문, 특수문자를 두가지이상 혼용하여야 합니다.");
        userpw.focus();
        return false;
    }
    
    // 동일한 문자/숫자 4이상, 연속된 문자
    if(/(\w)\1\1\1/.test(userpw.value) || isContinuedValue(userpw.value))
    {
        alert("비밀번호에 4자 이상의 연속 또는 반복 문자 및 숫자를 사용하실 수 없습니다.");
        userpw.focus();
        return false;
    }

    // userpw_ch
    if(userpw_ch.value == '') {
        alert('비밀번호 확인란을 입력해주세요.');
        userpw_ch.focus();
        return false;
    }

    if(userpw.value != userpw_ch.value) {
        alert('비밀번호가 다릅니다. 다시 입력해주세요.');
        userpw_ch.focus();
        return false;
    }

    // Email
    if(Email.value == '') {
        alert('이메일을 입력해주세요.');
        Email.focus();
        return false;
    }

    const expEmailText = /^[A-Za-z0-9\.\-]+@[A-Za-z0-9\.\-]+\.[A-Za-z0-9\.\-]+$/;
    if(!expEmailText.test(Email.value)) {
        alert('이메일 형식을 확인해 주세요.');
        Email.focus();
        return false;
    }

    return true;
}

function isContinuedValue(value) {
    console.log("value = " + value);
    var intCnt1 = 0;
    var intCnt2 = 0;
    var temp0 = "";
    var temp1 = "";
    var temp2 = "";
    var temp3 = "";

    for (var i = 0; i < value.length-3; i++) {
        temp0 = value.charAt(i);
        temp1 = value.charAt(i + 1);
        temp2 = value.charAt(i + 2);
        temp3 = value.charAt(i + 3);

        if (temp0.charCodeAt(0) - temp1.charCodeAt(0) == 1
                && temp1.charCodeAt(0) - temp2.charCodeAt(0) == 1
                && temp2.charCodeAt(0) - temp3.charCodeAt(0) == 1) {
            intCnt1 = intCnt1 + 1;
        }

        if (temp0.charCodeAt(0) - temp1.charCodeAt(0) == -1
                && temp1.charCodeAt(0) - temp2.charCodeAt(0) == -1
                && temp2.charCodeAt(0) - temp3.charCodeAt(0) == -1) {
            intCnt2 = intCnt2 + 1;
        }

    }

    console.log(intCnt1 > 0 || intCnt2 > 0);
    return (intCnt1 > 0 || intCnt2 > 0);
}