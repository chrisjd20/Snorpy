$("#particles-js").fadeTo(0, 0.2);
$(".contentpluses").fadeTo(0, 0.6);
$(".contentpluses").hover( function() {
    $('#' + this.id).fadeTo(100, 1);
});
$(".contentpluses").mouseout( function() {
    $('#' + this.id).fadeTo(100, 0.6);
});

$("#contentdiv").fadeOut( 0 );
$("#pcrediv").fadeOut( 0 );
$(".plusexplode").click(function(){
    if (this.id == 'contentArrow1'){
        $("#contentplus").toggle( "drop" );
        $("#contentdiv").fadeIn( 400 );
    } else {
        $("#preplus").toggle( "drop" );
        $("#pcrediv").fadeIn( 400 );
    }
});
$("#contentcancel").click(function() {
    $("#contentdiv").fadeOut( 400 );
    $("#contentplus").toggle( "drop" );
});
$("#pcrecancel").click(function() {
    $("#pcrediv").fadeOut( 400 );
    $("#preplus").toggle( "drop" );
});

$(".selectedProtoOptions").fadeOut(0);
$(".headerelement").fadeTo(0, 0.3);
$(".headerelement").prop('disabled', true);
$('body').on('change', '#protoForm', function(){
    $(".selectedProtoOptions").fadeOut(400);
    var theval = $("#protoForm").val();
    if (theval === "Protocol") {
        $("#opprotocol").text('');
        $(".headerelement").fadeTo(0, 0.3);
        $(".headerelement").prop('disabled', true);
        $("#opudp").css('display', 'none');
        $("#opip").css('display', 'none');
        $("#opimcp").css('display', 'none');
        $("#optcp").css('display', 'none');
    } else if (theval === "tcp") {
        $("#opprotocol").text('tcp ');
        $(".headerelement").fadeTo(0, 1);
        $(".headerelement").prop('disabled', false);
        $("#srcport").prop('disabled', false);
        $("#dstport").prop('disabled', false);
        $("#srcport").fadeTo(100, 1);
        $("#dstport").fadeTo(100, 1);
        $("#tcp").fadeIn(400);
        $("#opudp").css('display', 'none');
        $("#opip").css('display', 'none');
        $("#opimcp").css('display', 'none');
        $("#optcp").css('display', 'inline-block');
        $("#opsrcport").css('display', 'inline-block');
        $("#opdstport").css('display', 'inline-block');
    } else if (theval === "udp") {
        $("#opprotocol").text('udp ');
        $(".headerelement").fadeTo(0, 1);
        $(".headerelement").prop('disabled', false);
        $("#srcport").prop('disabled', false);
        $("#dstport").prop('disabled', false);
        $("#srcport").fadeTo(100, 1);
        $("#dstport").fadeTo(100, 1);
        $("#udp").fadeIn(400);
        $("#opudp").css('display', 'inline-block');
        $("#opip").css('display', 'none');
        $("#opimcp").css('display', 'none');
        $("#optcp").css('display', 'none');
        $("#opsrcport").css('display', 'inline-block');
        $("#opdstport").css('display', 'inline-block');
    } else if (theval === "icmp") {
        $("#opprotocol").text('icmp ');
        $(".headerelement").fadeTo(0, 1);
        $(".headerelement").prop('disabled', false);
        $("#srcport").prop('disabled', true);
        $("#dstport").prop('disabled', true);
        $("#srcport").fadeTo(100, 0.3);
        $("#dstport").fadeTo(100, 0.3);
        $("#icmp").fadeIn(400);
        $("#opudp").css('display', 'none');
        $("#opip").css('display', 'none');
        $("#opimcp").css('display', 'inline-block');
        $("#optcp").css('display', 'none');
        $("#opsrcport").css('display', 'inline-block');
        $("#opdstport").css('display', 'inline-block');
        $("#opsrcport").text('any');
        $("#opdstport").text('any');
    } else if (theval === "ip") {
        $("#opprotocol").text('ip ');
        $(".headerelement").fadeTo(0, 1);
        $(".headerelement").prop('disabled', false);
        $("#srcport").prop('disabled', true);
        $("#dstport").prop('disabled', true);
        $("#srcport").fadeTo(100, 0.3);
        $("#dstport").fadeTo(100, 0.3);
        $("#ip").fadeIn(400);
        $("#opudp").css('display', 'none');
        $("#opip").css('display', 'inline-block');
        $("#opimcp").css('display', 'none');
        $("#optcp").css('display', 'none');
        $("#opsrcport").css('display', 'inline-block');
        $("#opdstport").css('display', 'inline-block');
        $("#opsrcport").text('any');
        $("#opdstport").text('any');

    }
});

var expression = /((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))/g;
var expression2 = /\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?\/\d\d?/g;
$('body').on('change', '#actionForm', function(){
    $("#opaction").text($("#actionForm").val() + ' ');
});

$("#srcip").focusout(function(){
    if ($("#srcip").val().match(expression) !== null  || $("#srcip").val().match(expression2) !== null || $("#srcip").val().match(/^(?:\!|\(|\$){1,2}(?:\.|\,|\w|\_|\d|\s|\!|\(|\))+\)?$/g) !== null || $("#srcip").val() === '' || $("#srcip").val() === 'any'){
        $("#opsrcip").text($("#srcip").val());
    } else {
        $("#srcip").clearQueue();
        $("#srcip").val("");
        $("#srcip").effect("shake");
    }
});
$("#dstip").focusout(function(){
    if ($("#dstip").val().match(expression) !== null  || $("#srcip").val().match(expression2) !== null || $("#dstip").val().match(/^(?:\!|\(|\$){1,2}(?:\.|\,|\w|\_|\d|\s|\!|\(|\))+\)?$/g) !== null || $("#dstip").val() === '' || $("#dstip").val() === 'any'){
        $("#opdstip").text($("#dstip").val());
    } else {
        $("#dstip").clearQueue();
        $("#dstip").val("");
        $("#dstip").effect("shake");
    }
});

$("#srcport").focusout(function(){
    if ($("#srcport").val() == "") {
        //do nothing
    } else if ($("#srcport").val() == "any") {
        $("#opsrcport").text($("#srcport").val()); 
    } else if ($("#srcport").val().match(/^(?:\$|\!|\(|\d){1}(?:\,|\$|\w|\_|\-|\d|\s|\!|\s)*\)?$/g) !== null || $("#srcport").val() === '' || $("#srcport").val() === 'any'){
        if (parseInt($("#srcport").val()) < 65535 && parseInt($("#srcport").val()) > 1) {
            $("#opsrcport").text($("#srcport").val())
        } else if ($("#srcport").val().match(/^(?:\$|\!|\(){1}(?:\$|\w)/g) !== null ) {
            $("#opsrcport").text($("#srcport").val());
        } else {
            $("#srcport").clearQueue();
            $("#srcport").val("");
            $("#srcport").effect("shake");
        }
    } else {
        $("#srcport").clearQueue();
        $("#srcport").val("");
        $("#srcport").effect("shake");
    }
});

$("#dstport").focusout(function(){
    if ($("#dstport").val() === '') {
        //do nothin
    } else if ($("#dstport").val() === 'any') {
        $("#opdstport").text($("#dstport").val());
    } else if ($("#dstport").val().match(/^(?:\$|\!|\(|\d){1}(?:\,|\$|\w|\_|\-|\d|\s|\!|\s)*\)?$/g) !== null || $("#dstport").val() === '' || $("#dstport").val() === 'any'){
        if (parseInt($("#dstport").val()) < 65535 && parseInt($("#dstport").val()) > 1) {
            $("#opdstport").text($("#dstport").val());
        } else if ($("#dstport").val().match(/^(?:\$|\!|\(){1}(?:\$|\w)/g) !== null) {
            $("#opdstport").text($("#dstport").val());
        } else {
            $("#dstport").clearQueue();
            $("#dstport").val("");
            $("#dstport").effect("shake");
        }
    } else {
        $("#dstport").clearQueue();
        $("#dstport").val("");
        $("#dstport").effect("shake");
    }
});

$("#sid").focusout(function(){
    if ($("#sid").val() ==="") {
        $("#opsid").text($("#sid").val());
    } else if (parseInt($("#sid").val()) < 1 || $("#sid").val().match(/^\d+$/g) === null) {
        $("#sid").clearQueue();
        $("#sid").val("");
        $("#sid").effect("shake");
    } else {
        $("#opsid").text(" sid:" + $("#sid").val() + ';');
    }
});

$("#rev").focusout(function(){
    if ($("#rev").val() ==="") {
        $("#oprevnum").text($("#rev").val());
    } else if (parseInt($("#rev").val()) < 1 || $("#rev").val().match(/^\d+$/g) === null) {
        $("#rev").clearQueue();
        $("#rev").val("");
        $("#rev").effect("shake");
    } else {
        $("#oprevnum").text("rev:" + $("#rev").val()+ ';');
    }
});

$("#headermessage").focusout(function(){
    if ($("#headermessage").val() ==="") {
        $("#opmessage").text($("#headermessage").val());
    } else if ($("#headermessage").val().match(/^(?:\w|\d|\.|\\\W|\s)+$/g) === null) {
        $("#headermessage").clearQueue();
        $("#headermessage").val("");
        $("#headermessage").effect("shake");
    } else {
        $("#opmessage").text("msg:\"" + $("#headermessage").val() + '";');
    }
});

$("#classtype").focusout(function(){
    if ($("#classtype").val() ==="") {
        $("#opclasstype").text($("#classtype").val());
    } else if ($("#classtype").val().match(/^\w(?:\w|\-)+\w$/g) === null) {
        $("#classtype").clearQueue();
        $("#classtype").val("");
        $("#classtype").effect("shake");
    } else {
        $("#opclasstype").text("classtype:" + $("#classtype").val() + ';');
    }
});

$("#gid").focusout(function(){
    if ($("#gid").val() ==="") {
        $("#opgid").text($("#gid").val());
    } else if ($("#gid").val().match(/^\d+$/g) === null) {
        $("#gid").clearQueue();
        $("#gid").val("");
        $("#gid").effect("shake");
    } else {
        $("#opgid").text("gid:" + $("#gid").val() + ';');
    }
});


$('body').on('change', '#priority', function(){
    $("#oppriority").text($("#priority").val());
});

$('body').on('change', '#httpmethodForm', function(){
    if ($("#httpmethodForm").val() === '') {
        $('#httpstatuscode').prop('disabled', false);
        $('#httpstatuscode').clearQueue();
        $('#httpstatuscode').fadeTo(200, 1);
        $("#opHttp").text($("#httpmethodForm").val());
    } else {
        $("#opHttp").text($("#httpmethodForm").val());
        $('#httpstatuscode').prop('disabled', true);
        $('#httpstatuscode').clearQueue();
        $('#httpstatuscode').fadeTo(200, 0.3);
    }
});

$('body').on('change', '#httpstatuscode', function(){
    if ($("#httpstatuscode").val() === '') {
        $('#httpmethodForm').prop('disabled', false);
        $('#httpmethodForm').clearQueue();
        $('#httpmethodForm').fadeTo(200, 1);
        $("#opHttp").text($("#httpmethodForm").val());
    } else {
        $("#opHttp").text("content:\""+$("#httpstatuscode").val() + "\"; http_stat_code;");
        $('#httpmethodForm').prop('disabled', true);
        $('#httpmethodForm').clearQueue();
        $('#httpmethodForm').fadeTo(200, 0.3);
    }
});

$(".opflags").click(function(){
    var theflags = '';
    if ($("#flagplus").is(':checked')) {
        theflags += '+';
    } else if ($("#wildcard").is(':checked')) {
        theflags += '*';
    }
    if ($("#ACK").is(':checked')) {
        theflags += 'A';
    }
    if ($("#SYN").is(':checked')) {
        theflags += 'S';
    }
    if ($("#PSH").is(':checked')) {
        theflags += 'P';
    }
    if ($("#RST").is(':checked')) {
        theflags += 'R';
    }
    if ($("#FIN").is(':checked')) {
        theflags += 'F';
    }
    if ($("#URG").is(':checked')) {
        theflags += 'U';
    }
    if (theflags === ""){
        $("#flagscombined").text('');
    } else {
        $("#flagscombined").text('flags:'+theflags + ';');
    }

});


$('body').on('change', '#tcpdirectionForm', function(){
    if ($("#tcpdirectionForm").val() === '') {
        $("#optcpdirection").text('');
    } else if ($("#tcpstateForm").val() === '' && $("#tcpdirectionForm").val() !== '') {
        $("#optcpdirection").text("flow:"+$("#tcpdirectionForm").val().toLowerCase()+";");
    } else if ($("#tcpdirectionForm").val() !== '') {
        $("#optcpdirection").text("flow:"+$("#tcpdirectionForm").val().toLowerCase() + ","+$("#tcpstateForm").val().toLowerCase()+";");
    }
});

$('body').on('change', '#tcpstateForm', function(){
    if ($("#tcpstateForm").val() === '' && $("#tcpdirectionForm").val() !== '') {
        $("#optcpdirection").text("flow:"+$("#tcpdirectionForm").val().toLowerCase()+";");
    } else if ($("#tcpdirectionForm").val() !== '') {
        $("#optcpdirection").text("flow:"+$("#tcpdirectionForm").val().toLowerCase() + ","+$("#tcpstateForm").val().toLowerCase()+";");
    }
});
//ICMP options icmptypeevaluator icmptype
//  icmpcodeevaluator icmpcode
$("#icmptype").focusout(function(){
    if ($("#icmptype").val() ==="") {
        $("#optype").text('');
    } else if ($("#icmptype").val().match(/^\d+$/g) !== null && $("#icmptypeevaluator").val() !== "") {
        $("#optype").text('itype:'+$("#icmptypeevaluator").val().replace('=','')+$("#icmptype").val() +';');
    } else {
        $("#icmptype").clearQueue();
        $("#icmptype").val("");
        $("#icmptype").effect("shake");
        $("#optype").text('');
    }
});

$('body').on('change', '#icmptypeevaluator', function(){
    if ($("#icmptype").val() ==="") {
        $("#optype").text('');
    } else if ($("#icmptype").val().match(/^\d+$/g) !== null && $("#icmptypeevaluator").val() !== "") {
        $("#optype").text('itype:'+$("#icmptypeevaluator").val().replace('=','')+$("#icmptype").val() +';');
    } else {
        $("#icmptype").clearQueue();
        $("#icmptype").val("");
        $("#icmptype").effect("shake");
        $("#optype").text('');
    }
});

$('body').on('change', '#icmpcodeevaluator', function(){
    if ($("#icmpcode").val() ==="") {
        $("#opcode").text('');
    } else if ($("#icmpcode").val().match(/^\d+$/g) !== null && $("#icmpcodeevaluator").val() !== "") {
        $("#opcode").text('icode:' + $("#icmpcodeevaluator").val().replace('=','') + $("#icmpcode").val() +';');
    } else {
        $("#icmpcode").clearQueue();
        $("#icmpcode").val("");
        $("#icmpcode").effect("shake");
        $("#opcode").text('');
    }
});

$("#icmpcode").focusout(function(){
    if ($("#icmpcode").val() ==="") {
        $("#opcode").text('');
    } else if ($("#icmpcode").val().match(/^\d+$/g) !== null && $("#icmpcodeevaluator").val() !== "") {
        $("#opcode").text('icode:' + $("#icmpcodeevaluator").val().replace('=','') + $("#icmpcode").val() +';');
    } else {
        $("#icmpcode").clearQueue();
        $("#icmpcode").val("");
        $("#icmpcode").effect("shake");
        $("#opcode").text('');
    }
});


$('body').on('change', '#udpdirectionForm', function(){
    if ($("#udpdirectionForm").val() === '') {
        $("#opudp").text('');
    } else {
        $("#opudp").text('flow:'+$("#udpdirectionForm").val().toLowerCase()+';');
    }
});



// IP OPTIONS
$("#ttl").focusout(function(){
    if ($("#ttl").val() ==="") {
        $("#opttl").text('');
    } else if ($("#ttl").val().match(/^\d+$/g) !== null && $("#ttlevaluator").val() !== "") {
        $("#opttl").text('ttl:'+$("#ttlevaluator").val().replace('=','')+$("#ttl").val() +';');
    } else {
        $("#ttl").clearQueue();
        $("#ttl").val("");
        $("#ttl").effect("shake");
        $("#opttl").text('');
    }
});

$('body').on('change', '#ttlevaluator', function(){
    if ($("#ttl").val() ==="") {
        $("#opttl").text('');
    } else if ($("#ttl").val().match(/^\d+$/g) !== null && $("#ttlevaluator").val() !== "") {
        $("#opttl").text('ttl:'+$("#ttlevaluator").val().replace('=','')+$("#ttl").val() +';');
    } else {
        $("#ttl").clearQueue();
        $("#ttl").val("");
        $("#ttl").effect("shake");
        $("#opttl").text('');
    }
});

$('body').on('change', '#ipprotoevaluator', function(){
    if ($("#ipprotofield").val() ==="") {
        $("#opipprotocol").text('');
    } else if ($("#ipprotofield").val().match(/^\d+$/g) !== null && $("#ipprotoevaluator").val() !== "") {
        $("#opipprotocol").text('ip_proto:' + $("#ipprotoevaluator").val().replace('=','') + $("#ipprotofield").val() +';');
    } else {
        $("#ipprotofield").clearQueue();
        $("#ipprotofield").val("");
        $("#ipprotofield").effect("shake");
        $("#opipprotocol").text('');
    }
});

$("#ipprotofield").focusout(function(){
    if ($("#ipprotofield").val() ==="") {
        $("#opipprotocol").text('');
    } else if ($("#ipprotofield").val().match(/^\d+$/g) !== null && $("#ipprotoevaluator").val() !== "") {
        $("#opipprotocol").text('ip_proto:' + $("#ipprotoevaluator").val().replace('=','') + $("#ipprotofield").val() +';');
    } else {
        $("#ipprotofield").clearQueue();
        $("#ipprotofield").val("");
        $("#ipprotofield").effect("shake");
        $("#opipprotocol").text('');
    }
});

//misc options
//datasize
$('body').on('change', '#datasizeEval', function(){
    if ($("#datasize").val() === '' || $("#datasizeEval").val() === '') {
        $("#opdatasize").text('');
    } else if ($("#datasize").val().match(/^\d+$/g) === null) {
        $("#opdatasize").text('');
        $("#datasize").clearQueue();
        $("#datasize").val('');
        $("#datasize").effect('shake');
    } else {
        $("#opdatasize").text('dsize:'+$("#datasizeEval").val().replace('=','')+$("#datasize").val()+';');
    }
});

$("#datasize").focusout(function(){
    if ($("#datasize").val() === '' || $("#datasizeEval").val() === '') {
        $("#opdatasize").text('');
    } else if ($("#datasize").val().match(/^\d+$/g) === null) {
        $("#opdatasize").text('');
        $("#datasize").clearQueue();
        $("#datasize").val('');
        $("#datasize").effect('shake');
    } else {
        $("#opdatasize").text('dsize:'+$("#datasizeEval").val().replace('=','')+$("#datasize").val()+';');
    }
});
//reference type
$('body').on('change', '#reftype', function(){
    if ($("#referencetext").val() === '' || $("#reftype").val() === '') {
        $("#opreference").text('');
    } else if ($("#referencetext").val().match(/(?:\"|\'|\;|\:|\)|\(|\\|\||\`|\$|\&|\^|\%|\#|\!|\+|\=|\[|\]|\}|\{)/g) !== null) {
        $("#opreference").text('');
        $("#referencetext").clearQueue();
        $("#referencetext").val('');
        $("#referencetext").effect('shake');
    } else {
        $("#opreference").text('reference:'+$("#reftype").val().toLowerCase()+","+$("#referencetext").val()+';');
    }
});

$("#referencetext").focusout(function(){
    if ($("#referencetext").val() === '' || $("#reftype").val() === '') {
        $("#opreference").text('');
    } else if ($("#referencetext").val().match(/(?:\"|\'|\;|\:|\)|\(|\\|\||\`|\$|\&|\^|\%|\#|\!|\+|\=|\[|\]|\}|\{)/g) !== null) {
        $("#opreference").text('');
        $("#referencetext").clearQueue();
        $("#referencetext").val('');
        $("#referencetext").effect('shake');
    } else {
        $("#opreference").text('reference:'+$("#reftype").val().toLowerCase()+","+$("#referencetext").val()+';');
    }
});

function referenceUpdater() {
    if ($("#count").val() === "" || $("#seconds").val() === ""  || $("#thresholdtype").val() === ""  || $("#trackby").val() === "" ) {
        $("#opthreshold").text('');
    } else if ($("#count").val().match(/^\d+$/g) === null) {
        $("#count").clearQueue();
        $("#count").effect('shake');
        $("#count").val('');
    } else if ($("#seconds").val().match(/^\d+$/g) === null) {
        $("#seconds").clearQueue();
        $("#seconds").effect('shake');
        $("#seconds").val('');
    } else {
        $("#opthreshold").text('threshold:type '+$('#thresholdtype').val()+', track '+$("#trackby").val()+', count '+$("#count").val()+' , seconds '+$("#seconds").val()+';');
    }
};

//referencetext
$('body').on('change', '#thresholdtype', function(){
    referenceUpdater();
});

$('body').on('change', '#trackby', function(){
    referenceUpdater();
});

$("#count").focusout(function(){
    referenceUpdater();
});

$("#seconds").focusout(function(){
    referenceUpdater();
});

String.prototype.hexEncode = function(){
    var hex, i;

    var result = "";
    for (i=0; i<this.length; i++) {
        hex = this.charCodeAt(i).toString(16);
        result += ("000"+hex).slice(-4);
    }

    return result
}

$("#contentundo").click(function(){
    var thearray = $("#opcontentContainer").text().split('content:');
    thearray.pop();
    $("#opcontentContainer").text(thearray.join('content:'));
});

$(".diditinput").focusout(function() {
    if ($("#" + this.id).val().match(/^\d+$/g) !== null || $("#" + this.id).val() === "") {

    } else {
        $("#" + this.id).clearQueue();
        $("#" + this.id).effect('shake');
        $("#" + this.id).val('');
    }
});

//Content adder
$("#contentcheck").click(function(){
    if ($('#theoffset').val() !== '' && $('#theoffset').val().match(/^\d+$/g) !== null) {
        var theoffset = ' offset: ' + $('#theoffset').val() + ';';
    } else {
        var theoffset = '';
    }
    if ($('#thedepth').val() !== '' && $('#thedepth').val().match(/^\d+$/g) !== null) {
        var thedepth = ' depth: '  + $('#thedepth').val() + ';';
    } else {
        var thedepth = '';
    }
    if ($("#content1nocase").is(':checked')) {
        var nocase = ' nocase;';
    } else {
        var nocase = '';
    }
    if ($("#content1uri").is(':checked')) {
        var uri = ' http_uri;';
    } else {
        var uri = '';
    }
    if ($("#content1not").is(':checked')) {
        var not = '!';
    } else {
        var not = '';
    }

    if ($("#thecontent").val() !== "") {
        var beforecontent = $("#thecontent").val();
        var finalContent = '';
        for (var i = 0; i < beforecontent.length; i++) {
            if (beforecontent[i].match(/(?:\`|\~|\!|\@|\#|\$|\%|\^|\&|\*|\)|\(|\-|\_|\=|\+|\]|\[|\}|\{|\|\;|\:|'|"|\,|\<|\.|\>|\/|\?|\s)/g) !== null) {
                finalContent += '|'+beforecontent[i].hexEncode().split('00')[1]+'|';
            } else {
                finalContent += beforecontent[i];
            }
            if (parseInt(i) === (beforecontent.length -1)) {
                if ($("#opcontentContainer").text() === ""){
                    $("#opcontentContainer").text('content:'+not+'"'+finalContent.replace(/\|\|/g," ") + '";'+theoffset+thedepth+ nocase + uri);
                } else {
                    $("#opcontentContainer").text($("#opcontentContainer").text() + ' content:'+not+'"'+finalContent.replace(/\|\|/g," ") + '";'+theoffset+thedepth+ nocase + uri);
                }
            }
        }
    } else {
        $("#contentcheck").effect('shake');
    }
});


//pcre:"/TESTREGEX/ismxG";
//regexhandler
$("#pcrecheck").click(function(){

    if ($("#redotal").is(':checked')) {
        var redotal = 's';
    } else {
        var redotal = '';
    }
    if ($("#renocase").is(':checked')) {
        var renocase = 'i';
    } else {
        var renocase = '';
    }
    if ($("#regreedy").is(':checked')) {
        var regreedy = 'G';
    } else {
        var regreedy = '';
    }
    if ($("#renewline").is(':checked')) {
        var renewline = 'm';
    } else {
        var renewline = '';
    }
    if ($("#rewhitespace").is(':checked')) {
        var rewhitespace = 'x';
    } else {
        var rewhitespace = '';
    }

    var theregex = $("#theregex").val() + '/';
    if ($("#theregex").val() !== "" && $("#oppcre").text() === "") {
        $("#oppcre").text($("#oppcre").text() + ' pcre:"/' + theregex + renocase + redotal + renewline + rewhitespace + regreedy +  '";');
    } else if ($("#theregex").val() !== "") {
        $("#oppcre").text($("#oppcre").text() + ' pcre:"/' + theregex + renocase + redotal + renewline + rewhitespace + regreedy +  '";');
    } else {
        $("#pcrecheck").effect('shake');
    }
});

$("#pcreundo").click(function(){
    var thearray = $("#oppcre").text().split('pcre:');
    thearray.pop();
    $("#oppcre").text(thearray.join('pcre:'));
});


var wildcard = false;
var theplus = false;
$(".flagoptions").click(function(){
    if (this.id === 'wildcard') {
        if (wildcard) {
            $(".flagoptions").prop('checked', false);
            wildcard = false;
        } else {
            $(".flagoptions").prop('checked', false);
            $('#' + this.id).prop('checked', true);
            wildcard = true;
        }
    } else {
        if (theplus) {
            $(".flagoptions").prop('checked', false);
            theplus = false;
        } else {
            $(".flagoptions").prop('checked', false);
            $('#' + this.id).prop('checked', true);
            theplus = true;
        }
    }
});
$("#GlobalResults").fadeOut(0);
function CopyToClipboard(containerid) {
if (document.selection) { 
    var range = document.body.createTextRange();
    range.moveToElementText(document.getElementById(containerid));
    range.select().createTextRange();
    document.execCommand("Copy"); 

} else if (window.getSelection) {
    var range = document.createRange();
     range.selectNode(document.getElementById(containerid));
     window.getSelection().addRange(range);
     document.execCommand("Copy");
     $("#GlobalResults").text("Copied To Clipboard");
     $("#GlobalResults").clearQueue();
     $("#GlobalResults").css('display','block');
     $("#GlobalResults").fadeIn(400);
    setTimeout(function() {
        $("#GlobalResults").fadeOut(400);
        $("#GlobalResults").css('display','none');
        $("#GlobalResults").text("");
    }, 400);
}};
