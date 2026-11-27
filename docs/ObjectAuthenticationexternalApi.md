# ObjectAuthenticationexternalApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**authenticationexternalCreateObjectV1**](#authenticationexternalcreateobjectv1) | **POST** /1/object/authenticationexternal | Create a new Authenticationexternal|
|[**authenticationexternalDeleteObjectV1**](#authenticationexternaldeleteobjectv1) | **DELETE** /1/object/authenticationexternal/{pkiAuthenticationexternalID} | Delete an existing Authenticationexternal|
|[**authenticationexternalEditObjectV1**](#authenticationexternaleditobjectv1) | **PUT** /1/object/authenticationexternal/{pkiAuthenticationexternalID} | Edit an existing Authenticationexternal|
|[**authenticationexternalGetAutocompleteV2**](#authenticationexternalgetautocompletev2) | **GET** /2/object/authenticationexternal/getAutocomplete/{sSelector} | Retrieve Authenticationexternals and IDs|
|[**authenticationexternalGetListV1**](#authenticationexternalgetlistv1) | **GET** /1/object/authenticationexternal/getList | Retrieve Authenticationexternal list|
|[**authenticationexternalGetObjectV2**](#authenticationexternalgetobjectv2) | **GET** /2/object/authenticationexternal/{pkiAuthenticationexternalID} | Retrieve an existing Authenticationexternal|
|[**authenticationexternalResetAuthorizationV1**](#authenticationexternalresetauthorizationv1) | **POST** /1/object/authenticationexternal/{pkiAuthenticationexternalID}/resetAuthorization | Reset the Authenticationexternal authorization|

# **authenticationexternalCreateObjectV1**
> AuthenticationexternalCreateObjectV1Response authenticationexternalCreateObjectV1(authenticationexternalCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectAuthenticationexternalApi,
    Configuration,
    AuthenticationexternalCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAuthenticationexternalApi(configuration);

let authenticationexternalCreateObjectV1Request: AuthenticationexternalCreateObjectV1Request; //

const { status, data } = await apiInstance.authenticationexternalCreateObjectV1(
    authenticationexternalCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **authenticationexternalCreateObjectV1Request** | **AuthenticationexternalCreateObjectV1Request**|  | |


### Return type

**AuthenticationexternalCreateObjectV1Response**

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

# **authenticationexternalDeleteObjectV1**
> AuthenticationexternalDeleteObjectV1Response authenticationexternalDeleteObjectV1()



### Example

```typescript
import {
    ObjectAuthenticationexternalApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAuthenticationexternalApi(configuration);

let pkiAuthenticationexternalID: number; //The unique ID of the Authenticationexternal (default to undefined)

const { status, data } = await apiInstance.authenticationexternalDeleteObjectV1(
    pkiAuthenticationexternalID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiAuthenticationexternalID** | [**number**] | The unique ID of the Authenticationexternal | defaults to undefined|


### Return type

**AuthenticationexternalDeleteObjectV1Response**

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

# **authenticationexternalEditObjectV1**
> AuthenticationexternalEditObjectV1Response authenticationexternalEditObjectV1(authenticationexternalEditObjectV1Request)



### Example

```typescript
import {
    ObjectAuthenticationexternalApi,
    Configuration,
    AuthenticationexternalEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAuthenticationexternalApi(configuration);

let pkiAuthenticationexternalID: number; //The unique ID of the Authenticationexternal (default to undefined)
let authenticationexternalEditObjectV1Request: AuthenticationexternalEditObjectV1Request; //

const { status, data } = await apiInstance.authenticationexternalEditObjectV1(
    pkiAuthenticationexternalID,
    authenticationexternalEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **authenticationexternalEditObjectV1Request** | **AuthenticationexternalEditObjectV1Request**|  | |
| **pkiAuthenticationexternalID** | [**number**] | The unique ID of the Authenticationexternal | defaults to undefined|


### Return type

**AuthenticationexternalEditObjectV1Response**

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

# **authenticationexternalGetAutocompleteV2**
> AuthenticationexternalGetAutocompleteV2Response authenticationexternalGetAutocompleteV2()

Get the list of Authenticationexternal to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectAuthenticationexternalApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAuthenticationexternalApi(configuration);

let sSelector: 'All'; //The type of Authenticationexternals to return (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)

const { status, data } = await apiInstance.authenticationexternalGetAutocompleteV2(
    sSelector,
    eFilterActive,
    sQuery,
    acceptLanguage
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;All&#39;**]**Array<&#39;All&#39;>** | The type of Authenticationexternals to return | defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|


### Return type

**AuthenticationexternalGetAutocompleteV2Response**

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

# **authenticationexternalGetListV1**
> AuthenticationexternalGetListV1Response authenticationexternalGetListV1()

Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eAuthenticationexternalType | Salesforce<br>SalesforceSandbox |

### Example

```typescript
import {
    ObjectAuthenticationexternalApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAuthenticationexternalApi(configuration);

let eOrderBy: 'pkiAuthenticationexternalID_ASC' | 'pkiAuthenticationexternalID_DESC' | 'sAuthenticationexternalDescription_ASC' | 'sAuthenticationexternalDescription_DESC' | 'eAuthenticationexternalType_ASC' | 'eAuthenticationexternalType_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.authenticationexternalGetListV1(
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
| **eOrderBy** | [**&#39;pkiAuthenticationexternalID_ASC&#39; | &#39;pkiAuthenticationexternalID_DESC&#39; | &#39;sAuthenticationexternalDescription_ASC&#39; | &#39;sAuthenticationexternalDescription_DESC&#39; | &#39;eAuthenticationexternalType_ASC&#39; | &#39;eAuthenticationexternalType_DESC&#39;**]**Array<&#39;pkiAuthenticationexternalID_ASC&#39; &#124; &#39;pkiAuthenticationexternalID_DESC&#39; &#124; &#39;sAuthenticationexternalDescription_ASC&#39; &#124; &#39;sAuthenticationexternalDescription_DESC&#39; &#124; &#39;eAuthenticationexternalType_ASC&#39; &#124; &#39;eAuthenticationexternalType_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**AuthenticationexternalGetListV1Response**

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

# **authenticationexternalGetObjectV2**
> AuthenticationexternalGetObjectV2Response authenticationexternalGetObjectV2()



### Example

```typescript
import {
    ObjectAuthenticationexternalApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAuthenticationexternalApi(configuration);

let pkiAuthenticationexternalID: number; //The unique ID of the Authenticationexternal (default to undefined)

const { status, data } = await apiInstance.authenticationexternalGetObjectV2(
    pkiAuthenticationexternalID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiAuthenticationexternalID** | [**number**] | The unique ID of the Authenticationexternal | defaults to undefined|


### Return type

**AuthenticationexternalGetObjectV2Response**

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

# **authenticationexternalResetAuthorizationV1**
> AuthenticationexternalResetAuthorizationV1Response authenticationexternalResetAuthorizationV1(body)



### Example

```typescript
import {
    ObjectAuthenticationexternalApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAuthenticationexternalApi(configuration);

let pkiAuthenticationexternalID: number; // (default to undefined)
let body: object; //

const { status, data } = await apiInstance.authenticationexternalResetAuthorizationV1(
    pkiAuthenticationexternalID,
    body
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **body** | **object**|  | |
| **pkiAuthenticationexternalID** | [**number**] |  | defaults to undefined|


### Return type

**AuthenticationexternalResetAuthorizationV1Response**

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

