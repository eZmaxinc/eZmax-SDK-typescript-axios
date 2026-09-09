# ObjectPaymenttermApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**paymenttermCreateObjectV1**](#paymenttermcreateobjectv1) | **POST** /1/object/paymentterm | Create a new Paymentterm|
|[**paymenttermEditObjectV1**](#paymenttermeditobjectv1) | **PUT** /1/object/paymentterm/{pkiPaymenttermID} | Edit an existing Paymentterm|
|[**paymenttermGetAutocompleteV2**](#paymenttermgetautocompletev2) | **GET** /2/object/paymentterm/getAutocomplete/{sSelector} | Retrieve Paymentterms and IDs|
|[**paymenttermGetListV1**](#paymenttermgetlistv1) | **GET** /1/object/paymentterm/getList | Retrieve Paymentterm list|
|[**paymenttermGetObjectV2**](#paymenttermgetobjectv2) | **GET** /2/object/paymentterm/{pkiPaymenttermID} | Retrieve an existing Paymentterm|

# **paymenttermCreateObjectV1**
> PaymenttermCreateObjectV1Response paymenttermCreateObjectV1(paymenttermCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectPaymenttermApi,
    Configuration,
    PaymenttermCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectPaymenttermApi(configuration);

let paymenttermCreateObjectV1Request: PaymenttermCreateObjectV1Request; //

const { status, data } = await apiInstance.paymenttermCreateObjectV1(
    paymenttermCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **paymenttermCreateObjectV1Request** | **PaymenttermCreateObjectV1Request**|  | |


### Return type

**PaymenttermCreateObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **paymenttermEditObjectV1**
> PaymenttermEditObjectV1Response paymenttermEditObjectV1(paymenttermEditObjectV1Request)



### Example

```typescript
import {
    ObjectPaymenttermApi,
    Configuration,
    PaymenttermEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectPaymenttermApi(configuration);

let pkiPaymenttermID: number; // (default to undefined)
let paymenttermEditObjectV1Request: PaymenttermEditObjectV1Request; //

const { status, data } = await apiInstance.paymenttermEditObjectV1(
    pkiPaymenttermID,
    paymenttermEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **paymenttermEditObjectV1Request** | **PaymenttermEditObjectV1Request**|  | |
| **pkiPaymenttermID** | [**number**] |  | defaults to undefined|


### Return type

**PaymenttermEditObjectV1Response**

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

# **paymenttermGetAutocompleteV2**
> PaymenttermGetAutocompleteV2Response paymenttermGetAutocompleteV2()

Get the list of Paymentterm to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectPaymenttermApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectPaymenttermApi(configuration);

let sSelector: 'All'; //The type of Paymentterms to return (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)

const { status, data } = await apiInstance.paymenttermGetAutocompleteV2(
    sSelector,
    eFilterActive,
    sQuery,
    acceptLanguage
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;All&#39;**]**Array<&#39;All&#39;>** | The type of Paymentterms to return | defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|


### Return type

**PaymenttermGetAutocompleteV2Response**

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

# **paymenttermGetListV1**
> PaymenttermGetListV1Response paymenttermGetListV1()


### Example

```typescript
import {
    ObjectPaymenttermApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectPaymenttermApi(configuration);

let eOrderBy: 'pkiPaymenttermID_ASC' | 'pkiPaymenttermID_DESC' | 'sPaymenttermCode_ASC' | 'sPaymenttermCode_DESC' | 'ePaymenttermType_ASC' | 'ePaymenttermType_DESC' | 'iPaymenttermDay_ASC' | 'iPaymenttermDay_DESC' | 'sPaymenttermDescriptionX_ASC' | 'sPaymenttermDescriptionX_DESC' | 'bPaymenttermIsactive_ASC' | 'bPaymenttermIsactive_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.paymenttermGetListV1(
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
| **eOrderBy** | [**&#39;pkiPaymenttermID_ASC&#39; | &#39;pkiPaymenttermID_DESC&#39; | &#39;sPaymenttermCode_ASC&#39; | &#39;sPaymenttermCode_DESC&#39; | &#39;ePaymenttermType_ASC&#39; | &#39;ePaymenttermType_DESC&#39; | &#39;iPaymenttermDay_ASC&#39; | &#39;iPaymenttermDay_DESC&#39; | &#39;sPaymenttermDescriptionX_ASC&#39; | &#39;sPaymenttermDescriptionX_DESC&#39; | &#39;bPaymenttermIsactive_ASC&#39; | &#39;bPaymenttermIsactive_DESC&#39;**]**Array<&#39;pkiPaymenttermID_ASC&#39; &#124; &#39;pkiPaymenttermID_DESC&#39; &#124; &#39;sPaymenttermCode_ASC&#39; &#124; &#39;sPaymenttermCode_DESC&#39; &#124; &#39;ePaymenttermType_ASC&#39; &#124; &#39;ePaymenttermType_DESC&#39; &#124; &#39;iPaymenttermDay_ASC&#39; &#124; &#39;iPaymenttermDay_DESC&#39; &#124; &#39;sPaymenttermDescriptionX_ASC&#39; &#124; &#39;sPaymenttermDescriptionX_DESC&#39; &#124; &#39;bPaymenttermIsactive_ASC&#39; &#124; &#39;bPaymenttermIsactive_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**PaymenttermGetListV1Response**

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

# **paymenttermGetObjectV2**
> PaymenttermGetObjectV2Response paymenttermGetObjectV2()



### Example

```typescript
import {
    ObjectPaymenttermApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectPaymenttermApi(configuration);

let pkiPaymenttermID: number; // (default to undefined)

const { status, data } = await apiInstance.paymenttermGetObjectV2(
    pkiPaymenttermID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiPaymenttermID** | [**number**] |  | defaults to undefined|


### Return type

**PaymenttermGetObjectV2Response**

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

