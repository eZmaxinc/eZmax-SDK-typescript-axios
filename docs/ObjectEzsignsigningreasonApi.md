# ObjectEzsignsigningreasonApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**ezsignsigningreasonCreateObjectV1**](#ezsignsigningreasoncreateobjectv1) | **POST** /1/object/ezsignsigningreason | Create a new Ezsignsigningreason|
|[**ezsignsigningreasonEditObjectV1**](#ezsignsigningreasoneditobjectv1) | **PUT** /1/object/ezsignsigningreason/{pkiEzsignsigningreasonID} | Edit an existing Ezsignsigningreason|
|[**ezsignsigningreasonGetAutocompleteV2**](#ezsignsigningreasongetautocompletev2) | **GET** /2/object/ezsignsigningreason/getAutocomplete/{sSelector} | Retrieve Ezsignsigningreasons and IDs|
|[**ezsignsigningreasonGetListV1**](#ezsignsigningreasongetlistv1) | **GET** /1/object/ezsignsigningreason/getList | Retrieve Ezsignsigningreason list|
|[**ezsignsigningreasonGetObjectV2**](#ezsignsigningreasongetobjectv2) | **GET** /2/object/ezsignsigningreason/{pkiEzsignsigningreasonID} | Retrieve an existing Ezsignsigningreason|

# **ezsignsigningreasonCreateObjectV1**
> EzsignsigningreasonCreateObjectV1Response ezsignsigningreasonCreateObjectV1(ezsignsigningreasonCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectEzsignsigningreasonApi,
    Configuration,
    EzsignsigningreasonCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignsigningreasonApi(configuration);

let ezsignsigningreasonCreateObjectV1Request: EzsignsigningreasonCreateObjectV1Request; //

const { status, data } = await apiInstance.ezsignsigningreasonCreateObjectV1(
    ezsignsigningreasonCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignsigningreasonCreateObjectV1Request** | **EzsignsigningreasonCreateObjectV1Request**|  | |


### Return type

**EzsignsigningreasonCreateObjectV1Response**

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

# **ezsignsigningreasonEditObjectV1**
> EzsignsigningreasonEditObjectV1Response ezsignsigningreasonEditObjectV1(ezsignsigningreasonEditObjectV1Request)



### Example

```typescript
import {
    ObjectEzsignsigningreasonApi,
    Configuration,
    EzsignsigningreasonEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignsigningreasonApi(configuration);

let pkiEzsignsigningreasonID: number; //The unique ID of the Ezsignsigningreason (default to undefined)
let ezsignsigningreasonEditObjectV1Request: EzsignsigningreasonEditObjectV1Request; //

const { status, data } = await apiInstance.ezsignsigningreasonEditObjectV1(
    pkiEzsignsigningreasonID,
    ezsignsigningreasonEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **ezsignsigningreasonEditObjectV1Request** | **EzsignsigningreasonEditObjectV1Request**|  | |
| **pkiEzsignsigningreasonID** | [**number**] | The unique ID of the Ezsignsigningreason | defaults to undefined|


### Return type

**EzsignsigningreasonEditObjectV1Response**

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

# **ezsignsigningreasonGetAutocompleteV2**
> EzsignsigningreasonGetAutocompleteV2Response ezsignsigningreasonGetAutocompleteV2()

Get the list of Ezsignsigningreason to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectEzsignsigningreasonApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignsigningreasonApi(configuration);

let sSelector: 'All' | 'Active'; //The type of Ezsignsigningreasons to return (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)

const { status, data } = await apiInstance.ezsignsigningreasonGetAutocompleteV2(
    sSelector,
    eFilterActive,
    sQuery,
    acceptLanguage
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;All&#39; | &#39;Active&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39;>** | The type of Ezsignsigningreasons to return | defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|


### Return type

**EzsignsigningreasonGetAutocompleteV2Response**

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

# **ezsignsigningreasonGetListV1**
> EzsignsigningreasonGetListV1Response ezsignsigningreasonGetListV1()



### Example

```typescript
import {
    ObjectEzsignsigningreasonApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignsigningreasonApi(configuration);

let eOrderBy: 'pkiEzsignsigningreasonID_ASC' | 'pkiEzsignsigningreasonID_DESC' | 'sEzsignsigningreasonDescriptionX_ASC' | 'sEzsignsigningreasonDescriptionX_DESC' | 'bEzsignsigningreasonIsactive_ASC' | 'bEzsignsigningreasonIsactive_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.ezsignsigningreasonGetListV1(
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
| **eOrderBy** | [**&#39;pkiEzsignsigningreasonID_ASC&#39; | &#39;pkiEzsignsigningreasonID_DESC&#39; | &#39;sEzsignsigningreasonDescriptionX_ASC&#39; | &#39;sEzsignsigningreasonDescriptionX_DESC&#39; | &#39;bEzsignsigningreasonIsactive_ASC&#39; | &#39;bEzsignsigningreasonIsactive_DESC&#39;**]**Array<&#39;pkiEzsignsigningreasonID_ASC&#39; &#124; &#39;pkiEzsignsigningreasonID_DESC&#39; &#124; &#39;sEzsignsigningreasonDescriptionX_ASC&#39; &#124; &#39;sEzsignsigningreasonDescriptionX_DESC&#39; &#124; &#39;bEzsignsigningreasonIsactive_ASC&#39; &#124; &#39;bEzsignsigningreasonIsactive_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**EzsignsigningreasonGetListV1Response**

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

# **ezsignsigningreasonGetObjectV2**
> EzsignsigningreasonGetObjectV2Response ezsignsigningreasonGetObjectV2()



### Example

```typescript
import {
    ObjectEzsignsigningreasonApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectEzsignsigningreasonApi(configuration);

let pkiEzsignsigningreasonID: number; //The unique ID of the Ezsignsigningreason (default to undefined)

const { status, data } = await apiInstance.ezsignsigningreasonGetObjectV2(
    pkiEzsignsigningreasonID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiEzsignsigningreasonID** | [**number**] | The unique ID of the Ezsignsigningreason | defaults to undefined|


### Return type

**EzsignsigningreasonGetObjectV2Response**

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

