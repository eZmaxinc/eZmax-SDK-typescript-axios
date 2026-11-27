# ObjectPaymentgatewayApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**paymentgatewayCreateObjectV1**](#paymentgatewaycreateobjectv1) | **POST** /1/object/paymentgateway | Create a new Paymentgateway|
|[**paymentgatewayEditObjectV1**](#paymentgatewayeditobjectv1) | **PUT** /1/object/paymentgateway/{pkiPaymentgatewayID} | Edit an existing Paymentgateway|
|[**paymentgatewayGetAutocompleteV2**](#paymentgatewaygetautocompletev2) | **GET** /2/object/paymentgateway/getAutocomplete/{sSelector} | Retrieve Paymentgateways and IDs|
|[**paymentgatewayGetListV1**](#paymentgatewaygetlistv1) | **GET** /1/object/paymentgateway/getList | Retrieve Paymentgateway list|
|[**paymentgatewayGetObjectV2**](#paymentgatewaygetobjectv2) | **GET** /2/object/paymentgateway/{pkiPaymentgatewayID} | Retrieve an existing Paymentgateway|

# **paymentgatewayCreateObjectV1**
> PaymentgatewayCreateObjectV1Response paymentgatewayCreateObjectV1(paymentgatewayCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectPaymentgatewayApi,
    Configuration,
    PaymentgatewayCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectPaymentgatewayApi(configuration);

let paymentgatewayCreateObjectV1Request: PaymentgatewayCreateObjectV1Request; //

const { status, data } = await apiInstance.paymentgatewayCreateObjectV1(
    paymentgatewayCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **paymentgatewayCreateObjectV1Request** | **PaymentgatewayCreateObjectV1Request**|  | |


### Return type

**PaymentgatewayCreateObjectV1Response**

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

# **paymentgatewayEditObjectV1**
> PaymentgatewayEditObjectV1Response paymentgatewayEditObjectV1(paymentgatewayEditObjectV1Request)



### Example

```typescript
import {
    ObjectPaymentgatewayApi,
    Configuration,
    PaymentgatewayEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectPaymentgatewayApi(configuration);

let pkiPaymentgatewayID: number; //The unique ID of the Paymentgateway (default to undefined)
let paymentgatewayEditObjectV1Request: PaymentgatewayEditObjectV1Request; //

const { status, data } = await apiInstance.paymentgatewayEditObjectV1(
    pkiPaymentgatewayID,
    paymentgatewayEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **paymentgatewayEditObjectV1Request** | **PaymentgatewayEditObjectV1Request**|  | |
| **pkiPaymentgatewayID** | [**number**] | The unique ID of the Paymentgateway | defaults to undefined|


### Return type

**PaymentgatewayEditObjectV1Response**

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

# **paymentgatewayGetAutocompleteV2**
> PaymentgatewayGetAutocompleteV2Response paymentgatewayGetAutocompleteV2()

Get the list of Paymentgateway to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectPaymentgatewayApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectPaymentgatewayApi(configuration);

let sSelector: 'All'; //The type of Paymentgateways to return (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)

const { status, data } = await apiInstance.paymentgatewayGetAutocompleteV2(
    sSelector,
    eFilterActive,
    sQuery,
    acceptLanguage
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;All&#39;**]**Array<&#39;All&#39;>** | The type of Paymentgateways to return | defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|


### Return type

**PaymentgatewayGetAutocompleteV2Response**

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

# **paymentgatewayGetListV1**
> PaymentgatewayGetListV1Response paymentgatewayGetListV1()

Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | ePaymentgatewayProcessor | Moneris |

### Example

```typescript
import {
    ObjectPaymentgatewayApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectPaymentgatewayApi(configuration);

let eOrderBy: 'pkiPaymentgatewayID_ASC' | 'pkiPaymentgatewayID_DESC' | 'fkiCreditcardmerchantID_ASC' | 'fkiCreditcardmerchantID_DESC' | 'ePaymentgatewayProcessor_ASC' | 'ePaymentgatewayProcessor_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.paymentgatewayGetListV1(
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
| **eOrderBy** | [**&#39;pkiPaymentgatewayID_ASC&#39; | &#39;pkiPaymentgatewayID_DESC&#39; | &#39;fkiCreditcardmerchantID_ASC&#39; | &#39;fkiCreditcardmerchantID_DESC&#39; | &#39;ePaymentgatewayProcessor_ASC&#39; | &#39;ePaymentgatewayProcessor_DESC&#39;**]**Array<&#39;pkiPaymentgatewayID_ASC&#39; &#124; &#39;pkiPaymentgatewayID_DESC&#39; &#124; &#39;fkiCreditcardmerchantID_ASC&#39; &#124; &#39;fkiCreditcardmerchantID_DESC&#39; &#124; &#39;ePaymentgatewayProcessor_ASC&#39; &#124; &#39;ePaymentgatewayProcessor_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**PaymentgatewayGetListV1Response**

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

# **paymentgatewayGetObjectV2**
> PaymentgatewayGetObjectV2Response paymentgatewayGetObjectV2()



### Example

```typescript
import {
    ObjectPaymentgatewayApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectPaymentgatewayApi(configuration);

let pkiPaymentgatewayID: number; //The unique ID of the Paymentgateway (default to undefined)

const { status, data } = await apiInstance.paymentgatewayGetObjectV2(
    pkiPaymentgatewayID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiPaymentgatewayID** | [**number**] | The unique ID of the Paymentgateway | defaults to undefined|


### Return type

**PaymentgatewayGetObjectV2Response**

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

