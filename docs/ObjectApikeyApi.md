# ObjectApikeyApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**apikeyCreateObjectV2**](#apikeycreateobjectv2) | **POST** /2/object/apikey | Create a new Apikey|
|[**apikeyEditObjectV1**](#apikeyeditobjectv1) | **PUT** /1/object/apikey/{pkiApikeyID} | Edit an existing Apikey|
|[**apikeyEditPermissionsV1**](#apikeyeditpermissionsv1) | **PUT** /1/object/apikey/{pkiApikeyID}/editPermissions | Edit multiple Permissions|
|[**apikeyGenerateDelegatedCredentialsV1**](#apikeygeneratedelegatedcredentialsv1) | **POST** /1/object/apikey/generateDelegatedCredentials | Generate a delegated credentials|
|[**apikeyGetCorsV1**](#apikeygetcorsv1) | **GET** /1/object/apikey/{pkiApikeyID}/getCors | Retrieve an existing Apikey\&#39;s cors|
|[**apikeyGetListV1**](#apikeygetlistv1) | **GET** /1/object/apikey/getList | Retrieve Apikey list|
|[**apikeyGetObjectV2**](#apikeygetobjectv2) | **GET** /2/object/apikey/{pkiApikeyID} | Retrieve an existing Apikey|
|[**apikeyGetPermissionsV1**](#apikeygetpermissionsv1) | **GET** /1/object/apikey/{pkiApikeyID}/getPermissions | Retrieve an existing Apikey\&#39;s Permissions|
|[**apikeyGetSubnetsV1**](#apikeygetsubnetsv1) | **GET** /1/object/apikey/{pkiApikeyID}/getSubnets | Retrieve an existing Apikey\&#39;s subnets|
|[**apikeyRegenerateV1**](#apikeyregeneratev1) | **POST** /1/object/apikey/{pkiApikeyID}/regenerate | Regenerate the Apikey|

# **apikeyCreateObjectV2**
> ApikeyCreateObjectV2Response apikeyCreateObjectV2(apikeyCreateObjectV2Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectApikeyApi,
    Configuration,
    ApikeyCreateObjectV2Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectApikeyApi(configuration);

let apikeyCreateObjectV2Request: ApikeyCreateObjectV2Request; //

const { status, data } = await apiInstance.apikeyCreateObjectV2(
    apikeyCreateObjectV2Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **apikeyCreateObjectV2Request** | **ApikeyCreateObjectV2Request**|  | |


### Return type

**ApikeyCreateObjectV2Response**

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

# **apikeyEditObjectV1**
> ApikeyEditObjectV1Response apikeyEditObjectV1(apikeyEditObjectV1Request)



### Example

```typescript
import {
    ObjectApikeyApi,
    Configuration,
    ApikeyEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectApikeyApi(configuration);

let pkiApikeyID: number; //The unique ID of the Apikey (default to undefined)
let apikeyEditObjectV1Request: ApikeyEditObjectV1Request; //

const { status, data } = await apiInstance.apikeyEditObjectV1(
    pkiApikeyID,
    apikeyEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **apikeyEditObjectV1Request** | **ApikeyEditObjectV1Request**|  | |
| **pkiApikeyID** | [**number**] | The unique ID of the Apikey | defaults to undefined|


### Return type

**ApikeyEditObjectV1Response**

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

# **apikeyEditPermissionsV1**
> ApikeyEditPermissionsV1Response apikeyEditPermissionsV1(apikeyEditPermissionsV1Request)

Using this endpoint, you can edit multiple Permissions at the same time.

### Example

```typescript
import {
    ObjectApikeyApi,
    Configuration,
    ApikeyEditPermissionsV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectApikeyApi(configuration);

let pkiApikeyID: number; // (default to undefined)
let apikeyEditPermissionsV1Request: ApikeyEditPermissionsV1Request; //

const { status, data } = await apiInstance.apikeyEditPermissionsV1(
    pkiApikeyID,
    apikeyEditPermissionsV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **apikeyEditPermissionsV1Request** | **ApikeyEditPermissionsV1Request**|  | |
| **pkiApikeyID** | [**number**] |  | defaults to undefined|


### Return type

**ApikeyEditPermissionsV1Response**

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

# **apikeyGenerateDelegatedCredentialsV1**
> ApikeyGenerateDelegatedCredentialsV1Response apikeyGenerateDelegatedCredentialsV1(apikeyGenerateDelegatedCredentialsV1Request)



### Example

```typescript
import {
    ObjectApikeyApi,
    Configuration,
    ApikeyGenerateDelegatedCredentialsV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectApikeyApi(configuration);

let apikeyGenerateDelegatedCredentialsV1Request: ApikeyGenerateDelegatedCredentialsV1Request; //

const { status, data } = await apiInstance.apikeyGenerateDelegatedCredentialsV1(
    apikeyGenerateDelegatedCredentialsV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **apikeyGenerateDelegatedCredentialsV1Request** | **ApikeyGenerateDelegatedCredentialsV1Request**|  | |


### Return type

**ApikeyGenerateDelegatedCredentialsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **apikeyGetCorsV1**
> ApikeyGetCorsV1Response apikeyGetCorsV1()


### Example

```typescript
import {
    ObjectApikeyApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectApikeyApi(configuration);

let pkiApikeyID: number; // (default to undefined)

const { status, data } = await apiInstance.apikeyGetCorsV1(
    pkiApikeyID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiApikeyID** | [**number**] |  | defaults to undefined|


### Return type

**ApikeyGetCorsV1Response**

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

# **apikeyGetListV1**
> ApikeyGetListV1Response apikeyGetListV1()

Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---|

### Example

```typescript
import {
    ObjectApikeyApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectApikeyApi(configuration);

let eOrderBy: 'pkiApikeyID_ASC' | 'pkiApikeyID_DESC' | 'sApikeyDescriptionX_ASC' | 'sApikeyDescriptionX_DESC' | 'bApikeyIssigned_ASC' | 'bApikeyIssigned_DESC' | 'bApikeyIsactive_ASC' | 'bApikeyIsactive_DESC' | 'sUserFirstname_ASC' | 'sUserFirstname_DESC' | 'sUserLastname_ASC' | 'sUserLastname_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.apikeyGetListV1(
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
| **eOrderBy** | [**&#39;pkiApikeyID_ASC&#39; | &#39;pkiApikeyID_DESC&#39; | &#39;sApikeyDescriptionX_ASC&#39; | &#39;sApikeyDescriptionX_DESC&#39; | &#39;bApikeyIssigned_ASC&#39; | &#39;bApikeyIssigned_DESC&#39; | &#39;bApikeyIsactive_ASC&#39; | &#39;bApikeyIsactive_DESC&#39; | &#39;sUserFirstname_ASC&#39; | &#39;sUserFirstname_DESC&#39; | &#39;sUserLastname_ASC&#39; | &#39;sUserLastname_DESC&#39;**]**Array<&#39;pkiApikeyID_ASC&#39; &#124; &#39;pkiApikeyID_DESC&#39; &#124; &#39;sApikeyDescriptionX_ASC&#39; &#124; &#39;sApikeyDescriptionX_DESC&#39; &#124; &#39;bApikeyIssigned_ASC&#39; &#124; &#39;bApikeyIssigned_DESC&#39; &#124; &#39;bApikeyIsactive_ASC&#39; &#124; &#39;bApikeyIsactive_DESC&#39; &#124; &#39;sUserFirstname_ASC&#39; &#124; &#39;sUserFirstname_DESC&#39; &#124; &#39;sUserLastname_ASC&#39; &#124; &#39;sUserLastname_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**ApikeyGetListV1Response**

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

# **apikeyGetObjectV2**
> ApikeyGetObjectV2Response apikeyGetObjectV2()



### Example

```typescript
import {
    ObjectApikeyApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectApikeyApi(configuration);

let pkiApikeyID: number; //The unique ID of the Apikey (default to undefined)

const { status, data } = await apiInstance.apikeyGetObjectV2(
    pkiApikeyID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiApikeyID** | [**number**] | The unique ID of the Apikey | defaults to undefined|


### Return type

**ApikeyGetObjectV2Response**

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

# **apikeyGetPermissionsV1**
> ApikeyGetPermissionsV1Response apikeyGetPermissionsV1()


### Example

```typescript
import {
    ObjectApikeyApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectApikeyApi(configuration);

let pkiApikeyID: number; // (default to undefined)

const { status, data } = await apiInstance.apikeyGetPermissionsV1(
    pkiApikeyID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiApikeyID** | [**number**] |  | defaults to undefined|


### Return type

**ApikeyGetPermissionsV1Response**

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

# **apikeyGetSubnetsV1**
> ApikeyGetSubnetsV1Response apikeyGetSubnetsV1()


### Example

```typescript
import {
    ObjectApikeyApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectApikeyApi(configuration);

let pkiApikeyID: number; // (default to undefined)

const { status, data } = await apiInstance.apikeyGetSubnetsV1(
    pkiApikeyID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiApikeyID** | [**number**] |  | defaults to undefined|


### Return type

**ApikeyGetSubnetsV1Response**

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

# **apikeyRegenerateV1**
> ApikeyRegenerateV1Response apikeyRegenerateV1(apikeyRegenerateV1Request)



### Example

```typescript
import {
    ObjectApikeyApi,
    Configuration,
    ApikeyRegenerateV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectApikeyApi(configuration);

let pkiApikeyID: number; // (default to undefined)
let apikeyRegenerateV1Request: ApikeyRegenerateV1Request; //

const { status, data } = await apiInstance.apikeyRegenerateV1(
    pkiApikeyID,
    apikeyRegenerateV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **apikeyRegenerateV1Request** | **ApikeyRegenerateV1Request**|  | |
| **pkiApikeyID** | [**number**] |  | defaults to undefined|


### Return type

**ApikeyRegenerateV1Response**

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

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

