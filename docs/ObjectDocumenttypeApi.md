# ObjectDocumenttypeApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**documenttypeCreateObjectV1**](#documenttypecreateobjectv1) | **POST** /1/object/documenttype | Create a new Documenttype|
|[**documenttypeEditObjectV1**](#documenttypeeditobjectv1) | **PUT** /1/object/documenttype/{pkiDocumenttypeID} | Edit an existing Documenttype|
|[**documenttypeGetAutocompleteV2**](#documenttypegetautocompletev2) | **GET** /2/object/documenttype/getAutocomplete/{sSelector} | Retrieve Documenttypes and IDs|
|[**documenttypeGetListV1**](#documenttypegetlistv1) | **GET** /1/object/documenttype/getList | Retrieve Documenttype list|
|[**documenttypeGetObjectV2**](#documenttypegetobjectv2) | **GET** /2/object/documenttype/{pkiDocumenttypeID} | Retrieve an existing Documenttype|

# **documenttypeCreateObjectV1**
> DocumenttypeCreateObjectV1Response documenttypeCreateObjectV1(documenttypeCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectDocumenttypeApi,
    Configuration,
    DocumenttypeCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDocumenttypeApi(configuration);

let documenttypeCreateObjectV1Request: DocumenttypeCreateObjectV1Request; //

const { status, data } = await apiInstance.documenttypeCreateObjectV1(
    documenttypeCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **documenttypeCreateObjectV1Request** | **DocumenttypeCreateObjectV1Request**|  | |


### Return type

**DocumenttypeCreateObjectV1Response**

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

# **documenttypeEditObjectV1**
> DocumenttypeEditObjectV1Response documenttypeEditObjectV1(documenttypeEditObjectV1Request)



### Example

```typescript
import {
    ObjectDocumenttypeApi,
    Configuration,
    DocumenttypeEditObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDocumenttypeApi(configuration);

let pkiDocumenttypeID: number; //The unique ID of the Documenttype (default to undefined)
let documenttypeEditObjectV1Request: DocumenttypeEditObjectV1Request; //

const { status, data } = await apiInstance.documenttypeEditObjectV1(
    pkiDocumenttypeID,
    documenttypeEditObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **documenttypeEditObjectV1Request** | **DocumenttypeEditObjectV1Request**|  | |
| **pkiDocumenttypeID** | [**number**] | The unique ID of the Documenttype | defaults to undefined|


### Return type

**DocumenttypeEditObjectV1Response**

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

# **documenttypeGetAutocompleteV2**
> DocumenttypeGetAutocompleteV2Response documenttypeGetAutocompleteV2()

Get the list of Documenttype to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectDocumenttypeApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDocumenttypeApi(configuration);

let sSelector: 'All'; //The type of Documenttypes to return (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)

const { status, data } = await apiInstance.documenttypeGetAutocompleteV2(
    sSelector,
    eFilterActive,
    sQuery,
    acceptLanguage
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;All&#39;**]**Array<&#39;All&#39;>** | The type of Documenttypes to return | defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|


### Return type

**DocumenttypeGetAutocompleteV2Response**

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

# **documenttypeGetListV1**
> DocumenttypeGetListV1Response documenttypeGetListV1()

Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---|  | Agentbroker<br>Buyercontract<br>Inscription<br>NotAuthenticated<br>Otherincome<br>RejectedOfferToPurchase | | eDocumenttypeEzcom | PromiseToPurchase<br>Annex<br>Modification<br>CounterOffer<br>Conditions<br>BankApproval<br>Other | | eDocumenttypePrivacydefault | Administration<br>Administrator<br>All<br>Creator<br>Inscriptor<br>Myself<br>Seller | | eDocumenttypeStatusdefault | Not required<br>Required | | eDocumenttypeSalebyowner | All<br>Yes<br>No | | eDocumenttypeSaledisplaybyrole | InscriptorSeller<br>Inscriptor<br>Seller | | eDocumenttypeTransactiontype | All<br>Inscriptor<br>InscriptorOnly<br>Seller<br>SellerOnly<br>InscriptorSeller | | eDocumenttypeRepossession | All<br>No<br>Yes |

### Example

```typescript
import {
    ObjectDocumenttypeApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDocumenttypeApi(configuration);

let eOrderBy: 'pkiDocumenttypeID_ASC' | 'pkiDocumenttypeID_DESC' | 'sDocumenttypeNameX_ASC' | 'sDocumenttypeNameX_DESC' | 'sDocumenttypeDefaultfilename_ASC' | 'sDocumenttypeDefaultfilename_DESC' | 'bDocumenttypeShowagent_ASC' | 'bDocumenttypeShowagent_DESC' | 'bDocumenttypeIsactive_ASC' | 'bDocumenttypeIsactive_DESC' | 'bDocumenttypeIsrequired_ASC' | 'bDocumenttypeIsrequired_DESC' | 'bDocumenttypeSale_ASC' | 'bDocumenttypeSale_DESC' | 'bDocumenttypeRental_ASC' | 'bDocumenttypeRental_DESC' | 'bDocumenttypeReference_ASC' | 'bDocumenttypeReference_DESC' | 'bDocumenttypeMortgagereference_ASC' | 'bDocumenttypeMortgagereference_DESC' | 'bDocumenttypeEvaluation_ASC' | 'bDocumenttypeEvaluation_DESC' | 'bDocumenttypeConsultation_ASC' | 'bDocumenttypeConsultation_DESC' | 'bDocumenttypeOtherservices_ASC' | 'bDocumenttypeOtherservices_DESC' | 'bDocumenttypeForeclosedsale_ASC' | 'bDocumenttypeForeclosedsale_DESC' | 'bDocumenttypeCommercialfunding_ASC' | 'bDocumenttypeCommercialfunding_DESC' | 'bDocumenttypeCanafe_ASC' | 'bDocumenttypeCanafe_DESC' | 'eDocumenttypeEzcom_ASC' | 'eDocumenttypeEzcom_DESC' | 'eDocumenttypePrivacydefault_ASC' | 'eDocumenttypePrivacydefault_DESC' | 'eDocumenttypeStatusdefault_ASC' | 'eDocumenttypeStatusdefault_DESC' | 'eDocumenttypeSalebyowner_ASC' | 'eDocumenttypeSalebyowner_DESC' | 'eDocumenttypeSaledisplaybyrole_ASC' | 'eDocumenttypeSaledisplaybyrole_DESC' | 'eDocumenttypeTransactiontype_ASC' | 'eDocumenttypeTransactiontype_DESC' | 'eDocumenttypeRepossession_ASC' | 'eDocumenttypeRepossession_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.documenttypeGetListV1(
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
| **eOrderBy** | [**&#39;pkiDocumenttypeID_ASC&#39; | &#39;pkiDocumenttypeID_DESC&#39; | &#39;sDocumenttypeNameX_ASC&#39; | &#39;sDocumenttypeNameX_DESC&#39; | &#39;sDocumenttypeDefaultfilename_ASC&#39; | &#39;sDocumenttypeDefaultfilename_DESC&#39; | &#39;bDocumenttypeShowagent_ASC&#39; | &#39;bDocumenttypeShowagent_DESC&#39; | &#39;bDocumenttypeIsactive_ASC&#39; | &#39;bDocumenttypeIsactive_DESC&#39; | &#39;bDocumenttypeIsrequired_ASC&#39; | &#39;bDocumenttypeIsrequired_DESC&#39; | &#39;bDocumenttypeSale_ASC&#39; | &#39;bDocumenttypeSale_DESC&#39; | &#39;bDocumenttypeRental_ASC&#39; | &#39;bDocumenttypeRental_DESC&#39; | &#39;bDocumenttypeReference_ASC&#39; | &#39;bDocumenttypeReference_DESC&#39; | &#39;bDocumenttypeMortgagereference_ASC&#39; | &#39;bDocumenttypeMortgagereference_DESC&#39; | &#39;bDocumenttypeEvaluation_ASC&#39; | &#39;bDocumenttypeEvaluation_DESC&#39; | &#39;bDocumenttypeConsultation_ASC&#39; | &#39;bDocumenttypeConsultation_DESC&#39; | &#39;bDocumenttypeOtherservices_ASC&#39; | &#39;bDocumenttypeOtherservices_DESC&#39; | &#39;bDocumenttypeForeclosedsale_ASC&#39; | &#39;bDocumenttypeForeclosedsale_DESC&#39; | &#39;bDocumenttypeCommercialfunding_ASC&#39; | &#39;bDocumenttypeCommercialfunding_DESC&#39; | &#39;bDocumenttypeCanafe_ASC&#39; | &#39;bDocumenttypeCanafe_DESC&#39; | &#39;eDocumenttypeEzcom_ASC&#39; | &#39;eDocumenttypeEzcom_DESC&#39; | &#39;eDocumenttypePrivacydefault_ASC&#39; | &#39;eDocumenttypePrivacydefault_DESC&#39; | &#39;eDocumenttypeStatusdefault_ASC&#39; | &#39;eDocumenttypeStatusdefault_DESC&#39; | &#39;eDocumenttypeSalebyowner_ASC&#39; | &#39;eDocumenttypeSalebyowner_DESC&#39; | &#39;eDocumenttypeSaledisplaybyrole_ASC&#39; | &#39;eDocumenttypeSaledisplaybyrole_DESC&#39; | &#39;eDocumenttypeTransactiontype_ASC&#39; | &#39;eDocumenttypeTransactiontype_DESC&#39; | &#39;eDocumenttypeRepossession_ASC&#39; | &#39;eDocumenttypeRepossession_DESC&#39;**]**Array<&#39;pkiDocumenttypeID_ASC&#39; &#124; &#39;pkiDocumenttypeID_DESC&#39; &#124; &#39;sDocumenttypeNameX_ASC&#39; &#124; &#39;sDocumenttypeNameX_DESC&#39; &#124; &#39;sDocumenttypeDefaultfilename_ASC&#39; &#124; &#39;sDocumenttypeDefaultfilename_DESC&#39; &#124; &#39;bDocumenttypeShowagent_ASC&#39; &#124; &#39;bDocumenttypeShowagent_DESC&#39; &#124; &#39;bDocumenttypeIsactive_ASC&#39; &#124; &#39;bDocumenttypeIsactive_DESC&#39; &#124; &#39;bDocumenttypeIsrequired_ASC&#39; &#124; &#39;bDocumenttypeIsrequired_DESC&#39; &#124; &#39;bDocumenttypeSale_ASC&#39; &#124; &#39;bDocumenttypeSale_DESC&#39; &#124; &#39;bDocumenttypeRental_ASC&#39; &#124; &#39;bDocumenttypeRental_DESC&#39; &#124; &#39;bDocumenttypeReference_ASC&#39; &#124; &#39;bDocumenttypeReference_DESC&#39; &#124; &#39;bDocumenttypeMortgagereference_ASC&#39; &#124; &#39;bDocumenttypeMortgagereference_DESC&#39; &#124; &#39;bDocumenttypeEvaluation_ASC&#39; &#124; &#39;bDocumenttypeEvaluation_DESC&#39; &#124; &#39;bDocumenttypeConsultation_ASC&#39; &#124; &#39;bDocumenttypeConsultation_DESC&#39; &#124; &#39;bDocumenttypeOtherservices_ASC&#39; &#124; &#39;bDocumenttypeOtherservices_DESC&#39; &#124; &#39;bDocumenttypeForeclosedsale_ASC&#39; &#124; &#39;bDocumenttypeForeclosedsale_DESC&#39; &#124; &#39;bDocumenttypeCommercialfunding_ASC&#39; &#124; &#39;bDocumenttypeCommercialfunding_DESC&#39; &#124; &#39;bDocumenttypeCanafe_ASC&#39; &#124; &#39;bDocumenttypeCanafe_DESC&#39; &#124; &#39;eDocumenttypeEzcom_ASC&#39; &#124; &#39;eDocumenttypeEzcom_DESC&#39; &#124; &#39;eDocumenttypePrivacydefault_ASC&#39; &#124; &#39;eDocumenttypePrivacydefault_DESC&#39; &#124; &#39;eDocumenttypeStatusdefault_ASC&#39; &#124; &#39;eDocumenttypeStatusdefault_DESC&#39; &#124; &#39;eDocumenttypeSalebyowner_ASC&#39; &#124; &#39;eDocumenttypeSalebyowner_DESC&#39; &#124; &#39;eDocumenttypeSaledisplaybyrole_ASC&#39; &#124; &#39;eDocumenttypeSaledisplaybyrole_DESC&#39; &#124; &#39;eDocumenttypeTransactiontype_ASC&#39; &#124; &#39;eDocumenttypeTransactiontype_DESC&#39; &#124; &#39;eDocumenttypeRepossession_ASC&#39; &#124; &#39;eDocumenttypeRepossession_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**DocumenttypeGetListV1Response**

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

# **documenttypeGetObjectV2**
> DocumenttypeGetObjectV2Response documenttypeGetObjectV2()



### Example

```typescript
import {
    ObjectDocumenttypeApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDocumenttypeApi(configuration);

let pkiDocumenttypeID: number; //The unique ID of the Documenttype (default to undefined)

const { status, data } = await apiInstance.documenttypeGetObjectV2(
    pkiDocumenttypeID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDocumenttypeID** | [**number**] | The unique ID of the Documenttype | defaults to undefined|


### Return type

**DocumenttypeGetObjectV2Response**

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

