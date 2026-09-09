# ObjectUserApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**userCreateObjectV1**](#usercreateobjectv1) | **POST** /1/object/user | Create a new User|
|[**userCreateObjectV2**](#usercreateobjectv2) | **POST** /2/object/user | Create a new User|
|[**userEditColleaguesV2**](#usereditcolleaguesv2) | **PUT** /2/object/user/{pkiUserID}/editColleagues | Edit multiple Colleagues|
|[**userEditObjectV1**](#usereditobjectv1) | **PUT** /1/object/user/{pkiUserID} | Edit an existing User|
|[**userEditPermissionsV1**](#usereditpermissionsv1) | **PUT** /1/object/user/{pkiUserID}/editPermissions | Edit multiple Permissions|
|[**userGetApikeysV1**](#usergetapikeysv1) | **GET** /1/object/user/{pkiUserID}/getApikeys | Retrieve an existing User\&#39;s Apikeys|
|[**userGetAutocompleteV2**](#usergetautocompletev2) | **GET** /2/object/user/getAutocomplete/{sSelector} | Retrieve Users and IDs|
|[**userGetColleaguesV2**](#usergetcolleaguesv2) | **GET** /2/object/user/{pkiUserID}/getColleagues | Retrieve an existing User\&#39;s Colleagues|
|[**userGetEffectivePermissionsV1**](#usergeteffectivepermissionsv1) | **GET** /1/object/user/{pkiUserID}/getEffectivePermissions | Retrieve an existing User\&#39;s Effective Permissions|
|[**userGetEzmaxcustomeruserV1**](#usergetezmaxcustomeruserv1) | **GET** /1/object/user/{pkiUserID}/getEzmaxcustomeruser | Returns the Ezmaxcustomeruser for the User|
|[**userGetListV1**](#usergetlistv1) | **GET** /1/object/user/getList | Retrieve User list|
|[**userGetObjectV2**](#usergetobjectv2) | **GET** /2/object/user/{pkiUserID} | Retrieve an existing User|
|[**userGetPermissionsV1**](#usergetpermissionsv1) | **GET** /1/object/user/{pkiUserID}/getPermissions | Retrieve an existing User\&#39;s Permissions|
|[**userGetSubnetsV1**](#usergetsubnetsv1) | **GET** /1/object/user/{pkiUserID}/getSubnets | Retrieve an existing User\&#39;s Subnets|
|[**userGetUsergroupexternalsV1**](#usergetusergroupexternalsv1) | **GET** /1/object/user/{pkiUserID}/getUsergroupexternals | Get User\&#39;s Usergroupexternals|
|[**userGetUsergroupsV1**](#usergetusergroupsv1) | **GET** /1/object/user/{pkiUserID}/getUsergroups | Get User\&#39;s Usergroups|
|[**userImpersonateV1**](#userimpersonatev1) | **POST** /1/object/user/{pkiUserID}/impersonate | Impersonate the user|
|[**userSendPasswordResetV1**](#usersendpasswordresetv1) | **POST** /1/object/user/{pkiUserID}/sendPasswordReset | Send password reset|

# **userCreateObjectV1**
> UserCreateObjectV1Response userCreateObjectV1(userCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectUserApi,
    Configuration,
    UserCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUserApi(configuration);

let userCreateObjectV1Request: UserCreateObjectV1Request; //

const { status, data } = await apiInstance.userCreateObjectV1(
    userCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **userCreateObjectV1Request** | **UserCreateObjectV1Request**|  | |


### Return type

**UserCreateObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **userCreateObjectV2**
> UserCreateObjectV2Response userCreateObjectV2(userCreateObjectV2Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectUserApi,
    Configuration,
    UserCreateObjectV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUserApi(configuration);

let userCreateObjectV2Request: UserCreateObjectV2Request; //

const { status, data } = await apiInstance.userCreateObjectV2(
    userCreateObjectV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **userCreateObjectV2Request** | **UserCreateObjectV2Request**|  | |


### Return type

**UserCreateObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **userEditColleaguesV2**
> UserEditColleaguesV2Response userEditColleaguesV2(userEditColleaguesV2Request)

Using this endpoint, you can edit multiple Colleagues at the same time.

### Example

```typescript
import {
    ObjectUserApi,
    Configuration,
    UserEditColleaguesV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUserApi(configuration);

let pkiUserID: number; // (default to undefined)
let userEditColleaguesV2Request: UserEditColleaguesV2Request; //

const { status, data } = await apiInstance.userEditColleaguesV2(
    pkiUserID,
    userEditColleaguesV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **userEditColleaguesV2Request** | **UserEditColleaguesV2Request**|  | |
| **pkiUserID** | [**number**] |  | defaults to undefined|


### Return type

**UserEditColleaguesV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **userEditObjectV1**
> UserEditObjectV1Response userEditObjectV1(userEditObjectV1Request)



### Example

```typescript
import {
    ObjectUserApi,
    Configuration,
    UserEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUserApi(configuration);

let pkiUserID: number; //The unique ID of the User (default to undefined)
let userEditObjectV1Request: UserEditObjectV1Request; //

const { status, data } = await apiInstance.userEditObjectV1(
    pkiUserID,
    userEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **userEditObjectV1Request** | **UserEditObjectV1Request**|  | |
| **pkiUserID** | [**number**] | The unique ID of the User | defaults to undefined|


### Return type

**UserEditObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **userEditPermissionsV1**
> UserEditPermissionsV1Response userEditPermissionsV1(userEditPermissionsV1Request)

Using this endpoint, you can edit multiple Permissions at the same time.

### Example

```typescript
import {
    ObjectUserApi,
    Configuration,
    UserEditPermissionsV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUserApi(configuration);

let pkiUserID: number; // (default to undefined)
let userEditPermissionsV1Request: UserEditPermissionsV1Request; //

const { status, data } = await apiInstance.userEditPermissionsV1(
    pkiUserID,
    userEditPermissionsV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **userEditPermissionsV1Request** | **UserEditPermissionsV1Request**|  | |
| **pkiUserID** | [**number**] |  | defaults to undefined|


### Return type

**UserEditPermissionsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **userGetApikeysV1**
> UserGetApikeysV1Response userGetApikeysV1()


### Example

```typescript
import {
    ObjectUserApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUserApi(configuration);

let pkiUserID: number; // (default to undefined)

const { status, data } = await apiInstance.userGetApikeysV1(
    pkiUserID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiUserID** | [**number**] |  | defaults to undefined|


### Return type

**UserGetApikeysV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **userGetAutocompleteV2**
> UserGetAutocompleteV2Response userGetAutocompleteV2()

Get the list of User to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectUserApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUserApi(configuration);

let sSelector: 'AgentBrokerAssistant' | 'AgentBrokerEmployeeEzsignUserNormalWithoutEzmaxpartner' | 'AgentBrokerEmployeeEzsignUserNormal' | 'AgentBrokerEmployeeNormalBuiltIn' | 'AgentBrokerEzsignuserNormal' | 'ClonableUsers' | 'EzsignuserBuiltIn' | 'Ezsignuser' | 'Normal' | 'UsergroupDelegated'; //The type of Users to return (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)

const { status, data } = await apiInstance.userGetAutocompleteV2(
    sSelector,
    eFilterActive,
    sQuery,
    acceptLanguage
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;AgentBrokerAssistant&#39; | &#39;AgentBrokerEmployeeEzsignUserNormalWithoutEzmaxpartner&#39; | &#39;AgentBrokerEmployeeEzsignUserNormal&#39; | &#39;AgentBrokerEmployeeNormalBuiltIn&#39; | &#39;AgentBrokerEzsignuserNormal&#39; | &#39;ClonableUsers&#39; | &#39;EzsignuserBuiltIn&#39; | &#39;Ezsignuser&#39; | &#39;Normal&#39; | &#39;UsergroupDelegated&#39;**]**Array<&#39;AgentBrokerAssistant&#39; &#124; &#39;AgentBrokerEmployeeEzsignUserNormalWithoutEzmaxpartner&#39; &#124; &#39;AgentBrokerEmployeeEzsignUserNormal&#39; &#124; &#39;AgentBrokerEmployeeNormalBuiltIn&#39; &#124; &#39;AgentBrokerEzsignuserNormal&#39; &#124; &#39;ClonableUsers&#39; &#124; &#39;EzsignuserBuiltIn&#39; &#124; &#39;Ezsignuser&#39; &#124; &#39;Normal&#39; &#124; &#39;UsergroupDelegated&#39;>** | The type of Users to return | defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|


### Return type

**UserGetAutocompleteV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **userGetColleaguesV2**
> UserGetColleaguesV2Response userGetColleaguesV2()


### Example

```typescript
import {
    ObjectUserApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUserApi(configuration);

let pkiUserID: number; // (default to undefined)

const { status, data } = await apiInstance.userGetColleaguesV2(
    pkiUserID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiUserID** | [**number**] |  | defaults to undefined|


### Return type

**UserGetColleaguesV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **userGetEffectivePermissionsV1**
> UserGetEffectivePermissionsV1Response userGetEffectivePermissionsV1()

Effective Permissions refers to the combination of Permissions held by a User and the Permissions associated with the Usergroups they belong to.

### Example

```typescript
import {
    ObjectUserApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUserApi(configuration);

let pkiUserID: number; // (default to undefined)

const { status, data } = await apiInstance.userGetEffectivePermissionsV1(
    pkiUserID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiUserID** | [**number**] |  | defaults to undefined|


### Return type

**UserGetEffectivePermissionsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **userGetEzmaxcustomeruserV1**
> UserGetEzmaxcustomeruserV1Response userGetEzmaxcustomeruserV1()

Returns the Ezmaxcustomeruser for the User

### Example

```typescript
import {
    ObjectUserApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUserApi(configuration);

let pkiUserID: number; // (default to undefined)

const { status, data } = await apiInstance.userGetEzmaxcustomeruserV1(
    pkiUserID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiUserID** | [**number**] |  | defaults to undefined|


### Return type

**UserGetEzmaxcustomeruserV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **userGetListV1**
> UserGetListV1Response userGetListV1()

Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eUserType | AgentBroker<br>Assistant<br>Employee<br>EzsignUser<br>Normal | | eUserOrigin | BuiltIn<br>External | | eUserEzsignaccess | No<br>PaidByOffice<br>PerDocument<br>Prepaid |

### Example

```typescript
import {
    ObjectUserApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUserApi(configuration);

let eOrderBy: 'pkiUserID_ASC' | 'pkiUserID_DESC' | 'fkiAgentID_ASC' | 'fkiAgentID_DESC' | 'fkiBrokerID_ASC' | 'fkiBrokerID_DESC' | 'sUserFirstname_ASC' | 'sUserFirstname_DESC' | 'sUserLastname_ASC' | 'sUserLastname_DESC' | 'sUserLoginname_ASC' | 'sUserLoginname_DESC' | 'bUserIsactive_ASC' | 'bUserIsactive_DESC' | 'eUserType_ASC' | 'eUserType_DESC' | 'eUserOrigin_ASC' | 'eUserOrigin_DESC' | 'eUserEzsignaccess_ASC' | 'eUserEzsignaccess_DESC' | 'dtUserEzsignprepaidexpiration_ASC' | 'dtUserEzsignprepaidexpiration_DESC' | 'sEmailAddress_ASC' | 'sEmailAddress_DESC' | 'bUserSuspended_ASC' | 'bUserSuspended_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.userGetListV1(
    eOrderBy,
    iRowMax,
    iRowOffset,
    acceptLanguage,
    sFilter
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **eOrderBy** | [**&#39;pkiUserID_ASC&#39; | &#39;pkiUserID_DESC&#39; | &#39;fkiAgentID_ASC&#39; | &#39;fkiAgentID_DESC&#39; | &#39;fkiBrokerID_ASC&#39; | &#39;fkiBrokerID_DESC&#39; | &#39;sUserFirstname_ASC&#39; | &#39;sUserFirstname_DESC&#39; | &#39;sUserLastname_ASC&#39; | &#39;sUserLastname_DESC&#39; | &#39;sUserLoginname_ASC&#39; | &#39;sUserLoginname_DESC&#39; | &#39;bUserIsactive_ASC&#39; | &#39;bUserIsactive_DESC&#39; | &#39;eUserType_ASC&#39; | &#39;eUserType_DESC&#39; | &#39;eUserOrigin_ASC&#39; | &#39;eUserOrigin_DESC&#39; | &#39;eUserEzsignaccess_ASC&#39; | &#39;eUserEzsignaccess_DESC&#39; | &#39;dtUserEzsignprepaidexpiration_ASC&#39; | &#39;dtUserEzsignprepaidexpiration_DESC&#39; | &#39;sEmailAddress_ASC&#39; | &#39;sEmailAddress_DESC&#39; | &#39;bUserSuspended_ASC&#39; | &#39;bUserSuspended_DESC&#39;**]**Array<&#39;pkiUserID_ASC&#39; &#124; &#39;pkiUserID_DESC&#39; &#124; &#39;fkiAgentID_ASC&#39; &#124; &#39;fkiAgentID_DESC&#39; &#124; &#39;fkiBrokerID_ASC&#39; &#124; &#39;fkiBrokerID_DESC&#39; &#124; &#39;sUserFirstname_ASC&#39; &#124; &#39;sUserFirstname_DESC&#39; &#124; &#39;sUserLastname_ASC&#39; &#124; &#39;sUserLastname_DESC&#39; &#124; &#39;sUserLoginname_ASC&#39; &#124; &#39;sUserLoginname_DESC&#39; &#124; &#39;bUserIsactive_ASC&#39; &#124; &#39;bUserIsactive_DESC&#39; &#124; &#39;eUserType_ASC&#39; &#124; &#39;eUserType_DESC&#39; &#124; &#39;eUserOrigin_ASC&#39; &#124; &#39;eUserOrigin_DESC&#39; &#124; &#39;eUserEzsignaccess_ASC&#39; &#124; &#39;eUserEzsignaccess_DESC&#39; &#124; &#39;dtUserEzsignprepaidexpiration_ASC&#39; &#124; &#39;dtUserEzsignprepaidexpiration_DESC&#39; &#124; &#39;sEmailAddress_ASC&#39; &#124; &#39;sEmailAddress_DESC&#39; &#124; &#39;bUserSuspended_ASC&#39; &#124; &#39;bUserSuspended_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**UserGetListV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, application/vnd.openxmlformats-officedocument.spreadsheetml.sheet


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **userGetObjectV2**
> UserGetObjectV2Response userGetObjectV2()



### Example

```typescript
import {
    ObjectUserApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUserApi(configuration);

let pkiUserID: number; //The unique ID of the User (default to undefined)

const { status, data } = await apiInstance.userGetObjectV2(
    pkiUserID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiUserID** | [**number**] | The unique ID of the User | defaults to undefined|


### Return type

**UserGetObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **userGetPermissionsV1**
> UserGetPermissionsV1Response userGetPermissionsV1()


### Example

```typescript
import {
    ObjectUserApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUserApi(configuration);

let pkiUserID: number; // (default to undefined)

const { status, data } = await apiInstance.userGetPermissionsV1(
    pkiUserID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiUserID** | [**number**] |  | defaults to undefined|


### Return type

**UserGetPermissionsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **userGetSubnetsV1**
> UserGetSubnetsV1Response userGetSubnetsV1()


### Example

```typescript
import {
    ObjectUserApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUserApi(configuration);

let pkiUserID: number; // (default to undefined)

const { status, data } = await apiInstance.userGetSubnetsV1(
    pkiUserID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiUserID** | [**number**] |  | defaults to undefined|


### Return type

**UserGetSubnetsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **userGetUsergroupexternalsV1**
> UserGetUsergroupexternalsV1Response userGetUsergroupexternalsV1()


### Example

```typescript
import {
    ObjectUserApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUserApi(configuration);

let pkiUserID: number; // (default to undefined)

const { status, data } = await apiInstance.userGetUsergroupexternalsV1(
    pkiUserID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiUserID** | [**number**] |  | defaults to undefined|


### Return type

**UserGetUsergroupexternalsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **userGetUsergroupsV1**
> UserGetUsergroupsV1Response userGetUsergroupsV1()


### Example

```typescript
import {
    ObjectUserApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUserApi(configuration);

let pkiUserID: number; // (default to undefined)

const { status, data } = await apiInstance.userGetUsergroupsV1(
    pkiUserID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiUserID** | [**number**] |  | defaults to undefined|


### Return type

**UserGetUsergroupsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **userImpersonateV1**
> UserImpersonateV1Response userImpersonateV1(userImpersonateV1Request)

Using this endpoint, you can impersonate the user.

### Example

```typescript
import {
    ObjectUserApi,
    Configuration,
    UserImpersonateV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUserApi(configuration);

let pkiUserID: number; // (default to undefined)
let userImpersonateV1Request: UserImpersonateV1Request; //

const { status, data } = await apiInstance.userImpersonateV1(
    pkiUserID,
    userImpersonateV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **userImpersonateV1Request** | **UserImpersonateV1Request**|  | |
| **pkiUserID** | [**number**] |  | defaults to undefined|


### Return type

**UserImpersonateV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **userSendPasswordResetV1**
> UserSendPasswordResetV1Response userSendPasswordResetV1(body)

Send the password reset email

### Example

```typescript
import {
    ObjectUserApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUserApi(configuration);

let pkiUserID: number; // (default to undefined)
let body: object; //

const { status, data } = await apiInstance.userSendPasswordResetV1(
    pkiUserID,
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |
| **pkiUserID** | [**number**] |  | defaults to undefined|


### Return type

**UserSendPasswordResetV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

