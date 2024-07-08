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

    if(userpw.value.length < 6 || userpw.value.length > 20){
        alert("비밀번호는 6자 이상 20자 이하로 입력해주세요.");
        userpw.focus();
        return false;
    }

    // userpw_ch
    if(userpw_ch.value == '') {
        alert('비밀번호 확인을 입력해주세요.');
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