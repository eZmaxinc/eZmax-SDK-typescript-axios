# ObjectCreditcardclientApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**creditcardclientCreateObjectV1**](#creditcardclientcreateobjectv1) | **POST** /1/object/creditcardclient | Create a new Creditcardclient|
|[**creditcardclientDeleteObjectV1**](#creditcardclientdeleteobjectv1) | **DELETE** /1/object/creditcardclient/{pkiCreditcardclientID} | Delete an existing Creditcardclient|
|[**creditcardclientEditObjectV1**](#creditcardclienteditobjectv1) | **PUT** /1/object/creditcardclient/{pkiCreditcardclientID} | Edit an existing Creditcardclient|
|[**creditcardclientGetAutocompleteV2**](#creditcardclientgetautocompletev2) | **GET** /2/object/creditcardclient/getAutocomplete/{sSelector} | Retrieve Creditcardclients and IDs|
|[**creditcardclientGetListV1**](#creditcardclientgetlistv1) | **GET** /1/object/creditcardclient/getList | Retrieve Creditcardclient list|
|[**creditcardclientGetObjectV2**](#creditcardclientgetobjectv2) | **GET** /2/object/creditcardclient/{pkiCreditcardclientID} | Retrieve an existing Creditcardclient|
|[**creditcardclientPatchObjectV1**](#creditcardclientpatchobjectv1) | **PATCH** /1/object/creditcardclient/{pkiCreditcardclientID} | Patch an existing Creditcardclient|

# **creditcardclientCreateObjectV1**
> CreditcardclientCreateObjectV1Response creditcardclientCreateObjectV1(creditcardclientCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectCreditcardclientApi,
    Configuration,
    CreditcardclientCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCreditcardclientApi(configuration);

let creditcardclientCreateObjectV1Request: CreditcardclientCreateObjectV1Request; //

const { status, data } = await apiInstance.creditcardclientCreateObjectV1(
    creditcardclientCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **creditcardclientCreateObjectV1Request** | **CreditcardclientCreateObjectV1Request**|  | |


### Return type

**CreditcardclientCreateObjectV1Response**

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

# **creditcardclientDeleteObjectV1**
> CreditcardclientDeleteObjectV1Response creditcardclientDeleteObjectV1()



### Example

```typescript
import {
    ObjectCreditcardclientApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCreditcardclientApi(configuration);

let pkiCreditcardclientID: number; //The unique ID of the Creditcardclient (default to undefined)

const { status, data } = await apiInstance.creditcardclientDeleteObjectV1(
    pkiCreditcardclientID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiCreditcardclientID** | [**number**] | The unique ID of the Creditcardclient | defaults to undefined|


### Return type

**CreditcardclientDeleteObjectV1Response**

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

# **creditcardclientEditObjectV1**
> CreditcardclientEditObjectV1Response creditcardclientEditObjectV1(creditcardclientEditObjectV1Request)



### Example

```typescript
import {
    ObjectCreditcardclientApi,
    Configuration,
    CreditcardclientEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCreditcardclientApi(configuration);

let pkiCreditcardclientID: number; //The unique ID of the Creditcardclient (default to undefined)
let creditcardclientEditObjectV1Request: CreditcardclientEditObjectV1Request; //

const { status, data } = await apiInstance.creditcardclientEditObjectV1(
    pkiCreditcardclientID,
    creditcardclientEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **creditcardclientEditObjectV1Request** | **CreditcardclientEditObjectV1Request**|  | |
| **pkiCreditcardclientID** | [**number**] | The unique ID of the Creditcardclient | defaults to undefined|


### Return type

**CreditcardclientEditObjectV1Response**

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
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **creditcardclientGetAutocompleteV2**
> CreditcardclientGetAutocompleteV2Response creditcardclientGetAutocompleteV2()

Get the list of Creditcardclient to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectCreditcardclientApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCreditcardclientApi(configuration);

let sSelector: 'All'; //The type of Creditcardclients to return (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)

const { status, data } = await apiInstance.creditcardclientGetAutocompleteV2(
    sSelector,
    eFilterActive,
    sQuery,
    acceptLanguage
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;All&#39;**]**Array<&#39;All&#39;>** | The type of Creditcardclients to return | defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|


### Return type

**CreditcardclientGetAutocompleteV2Response**

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

# **creditcardclientGetListV1**
> CreditcardclientGetListV1Response creditcardclientGetListV1()



### Example

```typescript
import {
    ObjectCreditcardclientApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCreditcardclientApi(configuration);

let eOrderBy: 'pkiCreditcardclientID_ASC' | 'pkiCreditcardclientID_DESC' | 'fkiCreditcarddetailID_ASC' | 'fkiCreditcarddetailID_DESC' | 'fkiCreditcardtypeID_ASC' | 'fkiCreditcardtypeID_DESC' | 'bCreditcardclientrelationIsdefault_ASC' | 'bCreditcardclientrelationIsdefault_DESC' | 'bCreditcardclientLegacy_ASC' | 'bCreditcardclientLegacy_DESC' | 'sCreditcardclientDescription_ASC' | 'sCreditcardclientDescription_DESC' | 'bCreditcardclientIsactive_ASC' | 'bCreditcardclientIsactive_DESC' | 'bCreditcardclientAllowedagencypayment_ASC' | 'bCreditcardclientAllowedagencypayment_DESC' | 'bCreditcardclientAllowedtranquillit_ASC' | 'bCreditcardclientAllowedtranquillit_DESC' | 'iCreditcarddetailExpirationmonth_ASC' | 'iCreditcarddetailExpirationmonth_DESC' | 'iCreditcarddetailExpirationyear_ASC' | 'iCreditcarddetailExpirationyear_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.creditcardclientGetListV1(
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
| **eOrderBy** | [**&#39;pkiCreditcardclientID_ASC&#39; | &#39;pkiCreditcardclientID_DESC&#39; | &#39;fkiCreditcarddetailID_ASC&#39; | &#39;fkiCreditcarddetailID_DESC&#39; | &#39;fkiCreditcardtypeID_ASC&#39; | &#39;fkiCreditcardtypeID_DESC&#39; | &#39;bCreditcardclientrelationIsdefault_ASC&#39; | &#39;bCreditcardclientrelationIsdefault_DESC&#39; | &#39;bCreditcardclientLegacy_ASC&#39; | &#39;bCreditcardclientLegacy_DESC&#39; | &#39;sCreditcardclientDescription_ASC&#39; | &#39;sCreditcardclientDescription_DESC&#39; | &#39;bCreditcardclientIsactive_ASC&#39; | &#39;bCreditcardclientIsactive_DESC&#39; | &#39;bCreditcardclientAllowedagencypayment_ASC&#39; | &#39;bCreditcardclientAllowedagencypayment_DESC&#39; | &#39;bCreditcardclientAllowedtranquillit_ASC&#39; | &#39;bCreditcardclientAllowedtranquillit_DESC&#39; | &#39;iCreditcarddetailExpirationmonth_ASC&#39; | &#39;iCreditcarddetailExpirationmonth_DESC&#39; | &#39;iCreditcarddetailExpirationyear_ASC&#39; | &#39;iCreditcarddetailExpirationyear_DESC&#39;**]**Array<&#39;pkiCreditcardclientID_ASC&#39; &#124; &#39;pkiCreditcardclientID_DESC&#39; &#124; &#39;fkiCreditcarddetailID_ASC&#39; &#124; &#39;fkiCreditcarddetailID_DESC&#39; &#124; &#39;fkiCreditcardtypeID_ASC&#39; &#124; &#39;fkiCreditcardtypeID_DESC&#39; &#124; &#39;bCreditcardclientrelationIsdefault_ASC&#39; &#124; &#39;bCreditcardclientrelationIsdefault_DESC&#39; &#124; &#39;bCreditcardclientLegacy_ASC&#39; &#124; &#39;bCreditcardclientLegacy_DESC&#39; &#124; &#39;sCreditcardclientDescription_ASC&#39; &#124; &#39;sCreditcardclientDescription_DESC&#39; &#124; &#39;bCreditcardclientIsactive_ASC&#39; &#124; &#39;bCreditcardclientIsactive_DESC&#39; &#124; &#39;bCreditcardclientAllowedagencypayment_ASC&#39; &#124; &#39;bCreditcardclientAllowedagencypayment_DESC&#39; &#124; &#39;bCreditcardclientAllowedtranquillit_ASC&#39; &#124; &#39;bCreditcardclientAllowedtranquillit_DESC&#39; &#124; &#39;iCreditcarddetailExpirationmonth_ASC&#39; &#124; &#39;iCreditcarddetailExpirationmonth_DESC&#39; &#124; &#39;iCreditcarddetailExpirationyear_ASC&#39; &#124; &#39;iCreditcarddetailExpirationyear_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**CreditcardclientGetListV1Response**

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

# **creditcardclientGetObjectV2**
> CreditcardclientGetObjectV2Response creditcardclientGetObjectV2()



### Example

```typescript
import {
    ObjectCreditcardclientApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCreditcardclientApi(configuration);

let pkiCreditcardclientID: number; //The unique ID of the Creditcardclient (default to undefined)

const { status, data } = await apiInstance.creditcardclientGetObjectV2(
    pkiCreditcardclientID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiCreditcardclientID** | [**number**] | The unique ID of the Creditcardclient | defaults to undefined|


### Return type

**CreditcardclientGetObjectV2Response**

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

# **creditcardclientPatchObjectV1**
> CreditcardclientPatchObjectV1Response creditcardclientPatchObjectV1(creditcardclientPatchObjectV1Request)



### Example

```typescript
import {
    ObjectCreditcardclientApi,
    Configuration,
    CreditcardclientPatchObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectCreditcardclientApi(configuration);

let pkiCreditcardclientID: number; //The unique ID of the Creditcardclient (default to undefined)
let creditcardclientPatchObjectV1Request: CreditcardclientPatchObjectV1Request; //

const { status, data } = await apiInstance.creditcardclientPatchObjectV1(
    pkiCreditcardclientID,
    creditcardclientPatchObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **creditcardclientPatchObjectV1Request** | **CreditcardclientPatchObjectV1Request**|  | |
| **pkiCreditcardclientID** | [**number**] | The unique ID of the Creditcardclient | defaults to undefined|


### Return type

**CreditcardclientPatchObjectV1Response**

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

