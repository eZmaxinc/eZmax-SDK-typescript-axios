# ObjectUserstagedApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**userstagedCreateUserV1**](#userstagedcreateuserv1) | **POST** /1/object/userstaged/{pkiUserstagedID}/createUser | Create a User from a Userstaged and then map it|
|[**userstagedDeleteObjectV1**](#userstageddeleteobjectv1) | **DELETE** /1/object/userstaged/{pkiUserstagedID} | Delete an existing Userstaged|
|[**userstagedGetListV1**](#userstagedgetlistv1) | **GET** /1/object/userstaged/getList | Retrieve Userstaged list|
|[**userstagedGetObjectV2**](#userstagedgetobjectv2) | **GET** /2/object/userstaged/{pkiUserstagedID} | Retrieve an existing Userstaged|
|[**userstagedMapV1**](#userstagedmapv1) | **POST** /1/object/userstaged/{pkiUserstagedID}/map | Map the Userstaged to an existing user|

# **userstagedCreateUserV1**
> UserstagedCreateUserV1Response userstagedCreateUserV1(body)

Default values will be used while creating the User. If you need to change those values, you should use the route to edit a User.

### Example

```typescript
import {
    ObjectUserstagedApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUserstagedApi(configuration);

let pkiUserstagedID: number; // (default to undefined)
let body: object; //

const { status, data } = await apiInstance.userstagedCreateUserV1(
    pkiUserstagedID,
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |
| **pkiUserstagedID** | [**number**] |  | defaults to undefined|


### Return type

**UserstagedCreateUserV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **userstagedDeleteObjectV1**
> UserstagedDeleteObjectV1Response userstagedDeleteObjectV1()



### Example

```typescript
import {
    ObjectUserstagedApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUserstagedApi(configuration);

let pkiUserstagedID: number; // (default to undefined)

const { status, data } = await apiInstance.userstagedDeleteObjectV1(
    pkiUserstagedID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiUserstagedID** | [**number**] |  | defaults to undefined|


### Return type

**UserstagedDeleteObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **userstagedGetListV1**
> UserstagedGetListV1Response userstagedGetListV1()



### Example

```typescript
import {
    ObjectUserstagedApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUserstagedApi(configuration);

let eOrderBy: 'pkiUserstagedID_ASC' | 'pkiUserstagedID_DESC' | 'sEmailAddress_ASC' | 'sEmailAddress_DESC' | 'sUserstagedFirstname_ASC' | 'sUserstagedFirstname_DESC' | 'sUserstagedLastname_ASC' | 'sUserstagedLastname_DESC' | 'sUserstagedExternalid_ASC' | 'sUserstagedExternalid_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.userstagedGetListV1(
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
| **eOrderBy** | [**&#39;pkiUserstagedID_ASC&#39; | &#39;pkiUserstagedID_DESC&#39; | &#39;sEmailAddress_ASC&#39; | &#39;sEmailAddress_DESC&#39; | &#39;sUserstagedFirstname_ASC&#39; | &#39;sUserstagedFirstname_DESC&#39; | &#39;sUserstagedLastname_ASC&#39; | &#39;sUserstagedLastname_DESC&#39; | &#39;sUserstagedExternalid_ASC&#39; | &#39;sUserstagedExternalid_DESC&#39;**]**Array<&#39;pkiUserstagedID_ASC&#39; &#124; &#39;pkiUserstagedID_DESC&#39; &#124; &#39;sEmailAddress_ASC&#39; &#124; &#39;sEmailAddress_DESC&#39; &#124; &#39;sUserstagedFirstname_ASC&#39; &#124; &#39;sUserstagedFirstname_DESC&#39; &#124; &#39;sUserstagedLastname_ASC&#39; &#124; &#39;sUserstagedLastname_DESC&#39; &#124; &#39;sUserstagedExternalid_ASC&#39; &#124; &#39;sUserstagedExternalid_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**UserstagedGetListV1Response**

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

# **userstagedGetObjectV2**
> UserstagedGetObjectV2Response userstagedGetObjectV2()



### Example

```typescript
import {
    ObjectUserstagedApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUserstagedApi(configuration);

let pkiUserstagedID: number; // (default to undefined)

const { status, data } = await apiInstance.userstagedGetObjectV2(
    pkiUserstagedID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiUserstagedID** | [**number**] |  | defaults to undefined|


### Return type

**UserstagedGetObjectV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **userstagedMapV1**
> UserstagedMapV1Response userstagedMapV1(userstagedMapV1Request)



### Example

```typescript
import {
    ObjectUserstagedApi,
    Configuration,
    UserstagedMapV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectUserstagedApi(configuration);

let pkiUserstagedID: number; // (default to undefined)
let userstagedMapV1Request: UserstagedMapV1Request; //

const { status, data } = await apiInstance.userstagedMapV1(
    pkiUserstagedID,
    userstagedMapV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **userstagedMapV1Request** | **UserstagedMapV1Request**|  | |
| **pkiUserstagedID** | [**number**] |  | defaults to undefined|


### Return type

**UserstagedMapV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

