# ObjectCreditcardmerchantApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**creditcardmerchantGetAutocompleteV2**](#creditcardmerchantgetautocompletev2) | **GET** /2/object/creditcardmerchant/getAutocomplete/{sSelector} | Retrieve Creditcardmerchants and IDs|
|[**creditcardmerchantGetListV1**](#creditcardmerchantgetlistv1) | **GET** /1/object/creditcardmerchant/getList | Retrieve Creditcardmerchant list|
|[**creditcardmerchantGetObjectV2**](#creditcardmerchantgetobjectv2) | **GET** /2/object/creditcardmerchant/{pkiCreditcardmerchantID} | Retrieve an existing Creditcardmerchant|

# **creditcardmerchantGetAutocompleteV2**
> CreditcardmerchantGetAutocompleteV2Response creditcardmerchantGetAutocompleteV2()

Get the list of Creditcardmerchant to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectCreditcardmerchantApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCreditcardmerchantApi(configuration);

let sSelector: 'All'; //The type of Creditcardmerchants to return (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)

const { status, data } = await apiInstance.creditcardmerchantGetAutocompleteV2(
    sSelector,
    eFilterActive,
    sQuery,
    acceptLanguage
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;All&#39;**]**Array<&#39;All&#39;>** | The type of Creditcardmerchants to return | defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|


### Return type

**CreditcardmerchantGetAutocompleteV2Response**

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

# **creditcardmerchantGetListV1**
> CreditcardmerchantGetListV1Response creditcardmerchantGetListV1()



### Example

```typescript
import {
    ObjectCreditcardmerchantApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCreditcardmerchantApi(configuration);

let eOrderBy: 'pkiCreditcardmerchantID_ASC' | 'pkiCreditcardmerchantID_DESC' | 'fkiBankaccountID_ASC' | 'fkiBankaccountID_DESC' | 'fkiLanguageID_ASC' | 'fkiLanguageID_DESC' | 'bCreditcardmerchantDenyvisa_ASC' | 'bCreditcardmerchantDenyvisa_DESC' | 'bCreditcardmerchantDenymastercard_ASC' | 'bCreditcardmerchantDenymastercard_DESC' | 'bCreditcardmerchantDenyamex_ASC' | 'bCreditcardmerchantDenyamex_DESC' | 'bCreditcardmerchantIsactive_ASC' | 'bCreditcardmerchantIsactive_DESC' | 'sCreditcardmerchantDescription_ASC' | 'sCreditcardmerchantDescription_DESC' | 'sCreditcardmerchantStoreid_ASC' | 'sCreditcardmerchantStoreid_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.creditcardmerchantGetListV1(
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
| **eOrderBy** | [**&#39;pkiCreditcardmerchantID_ASC&#39; | &#39;pkiCreditcardmerchantID_DESC&#39; | &#39;fkiBankaccountID_ASC&#39; | &#39;fkiBankaccountID_DESC&#39; | &#39;fkiLanguageID_ASC&#39; | &#39;fkiLanguageID_DESC&#39; | &#39;bCreditcardmerchantDenyvisa_ASC&#39; | &#39;bCreditcardmerchantDenyvisa_DESC&#39; | &#39;bCreditcardmerchantDenymastercard_ASC&#39; | &#39;bCreditcardmerchantDenymastercard_DESC&#39; | &#39;bCreditcardmerchantDenyamex_ASC&#39; | &#39;bCreditcardmerchantDenyamex_DESC&#39; | &#39;bCreditcardmerchantIsactive_ASC&#39; | &#39;bCreditcardmerchantIsactive_DESC&#39; | &#39;sCreditcardmerchantDescription_ASC&#39; | &#39;sCreditcardmerchantDescription_DESC&#39; | &#39;sCreditcardmerchantStoreid_ASC&#39; | &#39;sCreditcardmerchantStoreid_DESC&#39;**]**Array<&#39;pkiCreditcardmerchantID_ASC&#39; &#124; &#39;pkiCreditcardmerchantID_DESC&#39; &#124; &#39;fkiBankaccountID_ASC&#39; &#124; &#39;fkiBankaccountID_DESC&#39; &#124; &#39;fkiLanguageID_ASC&#39; &#124; &#39;fkiLanguageID_DESC&#39; &#124; &#39;bCreditcardmerchantDenyvisa_ASC&#39; &#124; &#39;bCreditcardmerchantDenyvisa_DESC&#39; &#124; &#39;bCreditcardmerchantDenymastercard_ASC&#39; &#124; &#39;bCreditcardmerchantDenymastercard_DESC&#39; &#124; &#39;bCreditcardmerchantDenyamex_ASC&#39; &#124; &#39;bCreditcardmerchantDenyamex_DESC&#39; &#124; &#39;bCreditcardmerchantIsactive_ASC&#39; &#124; &#39;bCreditcardmerchantIsactive_DESC&#39; &#124; &#39;sCreditcardmerchantDescription_ASC&#39; &#124; &#39;sCreditcardmerchantDescription_DESC&#39; &#124; &#39;sCreditcardmerchantStoreid_ASC&#39; &#124; &#39;sCreditcardmerchantStoreid_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**CreditcardmerchantGetListV1Response**

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

# **creditcardmerchantGetObjectV2**
> CreditcardmerchantGetObjectV2Response creditcardmerchantGetObjectV2()



### Example

```typescript
import {
    ObjectCreditcardmerchantApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCreditcardmerchantApi(configuration);

let pkiCreditcardmerchantID: number; //The unique ID of the Creditcardmerchant (default to undefined)

const { status, data } = await apiInstance.creditcardmerchantGetObjectV2(
    pkiCreditcardmerchantID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiCreditcardmerchantID** | [**number**] | The unique ID of the Creditcardmerchant | defaults to undefined|


### Return type

**CreditcardmerchantGetObjectV2Response**

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

