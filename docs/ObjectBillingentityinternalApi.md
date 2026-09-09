# ObjectBillingentityinternalApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**billingentityinternalCreateObjectV1**](#billingentityinternalcreateobjectv1) | **POST** /1/object/billingentityinternal | Create a new Billingentityinternal|
|[**billingentityinternalEditObjectV1**](#billingentityinternaleditobjectv1) | **PUT** /1/object/billingentityinternal/{pkiBillingentityinternalID} | Edit an existing Billingentityinternal|
|[**billingentityinternalGetAutocompleteV2**](#billingentityinternalgetautocompletev2) | **GET** /2/object/billingentityinternal/getAutocomplete/{sSelector} | Retrieve Billingentityinternals and IDs|
|[**billingentityinternalGetListV1**](#billingentityinternalgetlistv1) | **GET** /1/object/billingentityinternal/getList | Retrieve Billingentityinternal list|
|[**billingentityinternalGetObjectV2**](#billingentityinternalgetobjectv2) | **GET** /2/object/billingentityinternal/{pkiBillingentityinternalID} | Retrieve an existing Billingentityinternal|

# **billingentityinternalCreateObjectV1**
> BillingentityinternalCreateObjectV1Response billingentityinternalCreateObjectV1(billingentityinternalCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectBillingentityinternalApi,
    Configuration,
    BillingentityinternalCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBillingentityinternalApi(configuration);

let billingentityinternalCreateObjectV1Request: BillingentityinternalCreateObjectV1Request; //

const { status, data } = await apiInstance.billingentityinternalCreateObjectV1(
    billingentityinternalCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **billingentityinternalCreateObjectV1Request** | **BillingentityinternalCreateObjectV1Request**|  | |


### Return type

**BillingentityinternalCreateObjectV1Response**

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

# **billingentityinternalEditObjectV1**
> BillingentityinternalEditObjectV1Response billingentityinternalEditObjectV1(billingentityinternalEditObjectV1Request)



### Example

```typescript
import {
    ObjectBillingentityinternalApi,
    Configuration,
    BillingentityinternalEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBillingentityinternalApi(configuration);

let pkiBillingentityinternalID: number; // (default to undefined)
let billingentityinternalEditObjectV1Request: BillingentityinternalEditObjectV1Request; //

const { status, data } = await apiInstance.billingentityinternalEditObjectV1(
    pkiBillingentityinternalID,
    billingentityinternalEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **billingentityinternalEditObjectV1Request** | **BillingentityinternalEditObjectV1Request**|  | |
| **pkiBillingentityinternalID** | [**number**] |  | defaults to undefined|


### Return type

**BillingentityinternalEditObjectV1Response**

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

# **billingentityinternalGetAutocompleteV2**
> BillingentityinternalGetAutocompleteV2Response billingentityinternalGetAutocompleteV2()

Get the list of Billingentityinternal to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectBillingentityinternalApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBillingentityinternalApi(configuration);

let sSelector: 'All'; //The type of Billingentityinternals to return (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)

const { status, data } = await apiInstance.billingentityinternalGetAutocompleteV2(
    sSelector,
    eFilterActive,
    sQuery,
    acceptLanguage
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;All&#39;**]**Array<&#39;All&#39;>** | The type of Billingentityinternals to return | defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|


### Return type

**BillingentityinternalGetAutocompleteV2Response**

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

# **billingentityinternalGetListV1**
> BillingentityinternalGetListV1Response billingentityinternalGetListV1()



### Example

```typescript
import {
    ObjectBillingentityinternalApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBillingentityinternalApi(configuration);

let eOrderBy: 'pkiBillingentityinternalID_ASC' | 'pkiBillingentityinternalID_DESC' | 'sBillingentityinternalDescriptionX_ASC' | 'sBillingentityinternalDescriptionX_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.billingentityinternalGetListV1(
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
| **eOrderBy** | [**&#39;pkiBillingentityinternalID_ASC&#39; | &#39;pkiBillingentityinternalID_DESC&#39; | &#39;sBillingentityinternalDescriptionX_ASC&#39; | &#39;sBillingentityinternalDescriptionX_DESC&#39;**]**Array<&#39;pkiBillingentityinternalID_ASC&#39; &#124; &#39;pkiBillingentityinternalID_DESC&#39; &#124; &#39;sBillingentityinternalDescriptionX_ASC&#39; &#124; &#39;sBillingentityinternalDescriptionX_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**BillingentityinternalGetListV1Response**

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

# **billingentityinternalGetObjectV2**
> BillingentityinternalGetObjectV2Response billingentityinternalGetObjectV2()



### Example

```typescript
import {
    ObjectBillingentityinternalApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBillingentityinternalApi(configuration);

let pkiBillingentityinternalID: number; // (default to undefined)

const { status, data } = await apiInstance.billingentityinternalGetObjectV2(
    pkiBillingentityinternalID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiBillingentityinternalID** | [**number**] |  | defaults to undefined|


### Return type

**BillingentityinternalGetObjectV2Response**

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

