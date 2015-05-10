
var ldap = require('ldapjs');


///--- Shared handlers

function authorize(req, res, next) {
  if (!req.connection.ldap.bindDN.equals('cn=root'))
    return next(new ldap.InsufficientAccessRightsError());

  return next();
}


///--- Globals

var SUFFIX = 'o=myhost';

var db = {};
var server = ldap.createServer();


function init(){
 db[SUFFIX]=  {
    dn:SUFFIX,
    attributes:{
      objectclass:['organization','top'],
      o:'myhost'
    }
  }
 db['ou=test,'+SUFFIX]=  {
    dn:'ou=test,'+SUFFIX,
    attributes:{
      objectclass:['organizationalUnit'],
      ou:'test'
    }
  }
}


server.bind('cn=root', function(req, res, next) {
  if (req.dn.toString() !== 'cn=root' || req.credentials !== 'password')
    return next(new ldap.InvalidCredentialsError());

  res.end();
  return next();
});

server.add(SUFFIX, authorize, function(req, res, next) {
  var dn = req.dn.toString();

  if (db[dn])
    return next(new ldap.EntryAlreadyExistsError(dn));

  db[dn] = req.toObject().attributes;
  res.end();
  return next();
});

server.bind(SUFFIX, function(req, res, next) {
  var dn = req.dn.toString();
  if (!db[dn])
    return next(new ldap.NoSuchObjectError(dn));

  if (!dn[dn].userpassword)
    return next(new ldap.NoSuchAttributeError('userPassword'));

  if (db[dn].userpassword !== req.credentials)
    return next(new ldap.InvalidCredentialsError());

  res.end();
  return next();
});

server.compare(SUFFIX, authorize, function(req, res, next) {
  var dn = req.dn.toString();
  if (!db[dn])
    return next(new ldap.NoSuchObjectError(dn));

  if (!db[dn][req.attribute])
    return next(new ldap.NoSuchAttributeError(req.attribute));

  var matches = false;
  var vals = db[dn][req.attribute];
  for (var i = 0; i <vals.length; i++) {
    if (vals[i] === req.value) {
      matches = true;
      break;
    }
  }

  res.end(matches);
  return next();
});

server.del(SUFFIX, authorize, function(req, res, next) {
  var dn = req.dn.toString();
  if (!db[dn])
    return next(new ldap.NoSuchObjectError(dn));

  delete db[dn];

  res.end();
  return next();
});

server.modify(SUFFIX, authorize, function(req, res, next) {
  var dn = req.dn.toString();
  if (!req.changes.length)
    return next(new ldap.ProtocolError('changes required'));
  if (!db[dn])
    return next(new ldap.NoSuchObjectError(dn));

  var entry = db[dn];

  for (var i = 0; i < req.changes.length; i++) {
    mod = req.changes[i].modification;
    switch (req.changes[i].operation) {
    case 'replace':
      if (!entry[mod.type])
        return next(new ldap.NoSuchAttributeError(mod.type));

      if (!mod.vals || !mod.vals.length) {
        delete entry[mod.type];
      } else {
        entry[mod.type] = mod.vals;
      }

      break;

    case 'add':
      if (!entry[mod.type]) {
        entry[mod.type] = mod.vals;
      } else {
        mod.vals.forEach(function(v) {
          if (entry[mod.type].indexOf(v) === -1)
            entry[mod.type].push(v);
        });
      }

      break;

    case 'delete':
      if (!entry[mod.type])
        return next(new ldap.NoSuchAttributeError(mod.type));

      delete entry[mod.type];

      break;
    }
  }

  res.end();
  return next();
});

server.search("",authorize, function(req, res, next) {
  var dn = req.dn.toString();
  console.log('LDAP server serch DSE= : %s', dn);


  var baseObject = {
		dn: '',
		structuralObjectClass: 'top',
		configContext: 'cn=config',
		attributes: {
			objectclass: ['top'],
			namingContexts: [SUFFIX],
			supportedLDAPVersion: ['3'],
			subschemaSubentry:['cn=Subschema']
		}
	};

   if('base' == req.scope
		&& '(objectclass=*)' == req.filter.toString()
		&& req.baseObject == ''){
		res.send(baseObject);
	}

//res.send({
   //dn:"",
   //attributes:{
   //     namingContexts:"",
   //     subschemaSubentry:"",
   //     supportedControl:["1.2.840.113556.1.4.319","1.2.840.113556.1.4.801","1.2.840.113556.1.4.473","1.2.840.113556.1.4.528","1.2.840.113556.1.4.417", "1.2.840.113556.1.4.619" ,"1.2.840.113556.1.4.841","1.2.840.113556.1.4.529" ,"1.2.840.113556.1.4.805" ,"1.2.840.113556.1.4.521" ,"1.2.840.113556.1.4.970" ,"1.2.840.113556.1.4.1338","1.2.840.113556.1.4.474" ,"1.2.840.113556.1.4.1339"],
   //     supportedLDAPVersion:3
   //     }
   //   });

  res.end();
  return next();
});

server.search('cn=Subschema',authorize, function(req, res, next) {
	var schema = {
		dn: 'cn=Subschema',
		attributes: {
			objectclass: ['top', 'subentry', 'subschema', 'extensibleObject'],
			cn: 'Subschema'
		}
	};
	res.send(schema);
	res.end();
	return next();
});


server.search(SUFFIX, authorize, function(req, res, next) {
  var dn = req.dn.toString();

  console.log('LDAP server serch dn= : %s', dn);
  if (!db[dn])
    return next(new ldap.NoSuchObjectError(dn));

  var scopeCheck;
  console.log('LDAP server serch scope= : %s', req.scope);

  //if(dn == SUFFIX && req.scope !='base' ){
 //   res.end();
 //   return next();
 // }

  switch (req.scope) {
  case 'base':
    //if (req.filter.matches(db[dn])) {
   //   res.send({
   //     dn: dn,
  //      attributes: db[dn]
 //     });
  //  }
  res.send(db[dn]);

    res.end();
    return next();

  case 'one':
    scopeCheck = function(k) {
      if (req.dn.equals(k)){
        console.log('LDAP server search keyskipchek: %s', k);
        return true;

      }else{
        var parent = ldap.parseDN(k).parent();
        console.log('LDAP server search keyone_k: %s', k);
        console.log('LDAP server search keyone_kp: %s', parent);
        console.log('LDAP server search keyone_ktf: %s', parent.equals(req.dn));

        return (parent ? parent.equals(req.dn) : false);
      }
    };
    break;

  case 'sub':
    scopeCheck = function(k) {
      return (req.dn.equals(k) || req.dn.parentOf(k));
    };

    break;
  }

  Object.keys(db).forEach(function(key) {
  console.log('LDAP server search object: %s', key);

    if (!scopeCheck(key)){
    console.log('LDAP server search keyskip: %s', key);
      return;
      }

 //   if (req.filter.matches(db[key])) {
  //    res.send({
   //     dn: key,
  //      attributes: db[key]
  //    });
  //  }
  console.log('LDAP server search key: %s', key);
    res.send(db[key]);
  });

  res.end();
  return next();
});



///--- Fire it up

server.listen(1389, function() {
  console.log('LDAP server up at: %s', server.url);
  init();
});
