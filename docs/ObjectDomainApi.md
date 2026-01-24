# ObjectDomainApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**domainCreateObjectV1**](#domaincreateobjectv1) | **POST** /1/object/domain | Create a new Domain|
|[**domainDeleteObjectV1**](#domaindeleteobjectv1) | **DELETE** /1/object/domain/{pkiDomainID} | Delete an existing Domain|
|[**domainGetAutocompleteV2**](#domaingetautocompletev2) | **GET** /2/object/domain/getAutocomplete/{sSelector} | Retrieve Domain and IDs|
|[**domainGetListV1**](#domaingetlistv1) | **GET** /1/object/domain/getList | Retrieve Domain list|
|[**domainGetObjectV2**](#domaingetobjectv2) | **GET** /2/object/domain/{pkiDomainID} | Retrieve an existing Domain|

# **domainCreateObjectV1**
> DomainCreateObjectV1Response domainCreateObjectV1(domainCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectDomainApi,
    Configuration,
    DomainCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDomainApi(configuration);

let domainCreateObjectV1Request: DomainCreateObjectV1Request; //

const { status, data } = await apiInstance.domainCreateObjectV1(
    domainCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **domainCreateObjectV1Request** | **DomainCreateObjectV1Request**|  | |


### Return type

**DomainCreateObjectV1Response**

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

# **domainDeleteObjectV1**
> DomainDeleteObjectV1Response domainDeleteObjectV1()



### Example

```typescript
import {
    ObjectDomainApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDomainApi(configuration);

let pkiDomainID: number; //The unique ID of the Domain (default to undefined)

const { status, data } = await apiInstance.domainDeleteObjectV1(
    pkiDomainID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDomainID** | [**number**] | The unique ID of the Domain | defaults to undefined|


### Return type

**DomainDeleteObjectV1Response**

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

# **domainGetAutocompleteV2**
> DomainGetAutocompleteV2Response domainGetAutocompleteV2()

Get the list of Domains to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectDomainApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDomainApi(configuration);

let sSelector: 'All' | 'ValidEmail'; //The type of Domain to return (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)

const { status, data } = await apiInstance.domainGetAutocompleteV2(
    sSelector,
    eFilterActive,
    sQuery,
    acceptLanguage
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;All&#39; | &#39;ValidEmail&#39;**]**Array<&#39;All&#39; &#124; &#39;ValidEmail&#39;>** | The type of Domain to return | defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|


### Return type

**DomainGetAutocompleteV2Response**

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

# **domainGetListV1**
> DomainGetListV1Response domainGetListV1()



### Example

```typescript
import {
    ObjectDomainApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDomainApi(configuration);

let eOrderBy: 'pkiDomainID_ASC' | 'pkiDomainID_DESC' | 'sDomainName_ASC' | 'sDomainName_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.domainGetListV1(
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
| **eOrderBy** | [**&#39;pkiDomainID_ASC&#39; | &#39;pkiDomainID_DESC&#39; | &#39;sDomainName_ASC&#39; | &#39;sDomainName_DESC&#39;**]**Array<&#39;pkiDomainID_ASC&#39; &#124; &#39;pkiDomainID_DESC&#39; &#124; &#39;sDomainName_ASC&#39; &#124; &#39;sDomainName_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**DomainGetListV1Response**

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

# **domainGetObjectV2**
> DomainGetObjectV2Response domainGetObjectV2()



### Example

```typescript
import {
    ObjectDomainApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDomainApi(configuration);

let pkiDomainID: number; //The unique ID of the Domain (default to undefined)

const { status, data } = await apiInstance.domainGetObjectV2(
    pkiDomainID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDomainID** | [**number**] | The unique ID of the Domain | defaults to undefined|


### Return type

**DomainGetObjectV2Response**

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

