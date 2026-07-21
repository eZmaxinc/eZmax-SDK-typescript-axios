# ObjectInscriptionnotauthenticatedApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**inscriptionnotauthenticatedFillInscriptionnotauthenticatedconditionV1**](#inscriptionnotauthenticatedfillinscriptionnotauthenticatedconditionv1) | **POST** /1/object/inscriptionnotauthenticated/{pkiInscriptionnotauthenticatedID}/fillInscriptionnotauthenticatedcondition | Fills the Inscriptionnotauthenticatedcondition in the Inscriptionnotauthenticated|
|[**inscriptionnotauthenticatedGetCommunicationCountV1**](#inscriptionnotauthenticatedgetcommunicationcountv1) | **GET** /1/object/inscriptionnotauthenticated/{pkiInscriptionnotauthenticatedID}/getCommunicationCount | Retrieve Communication count|
|[**inscriptionnotauthenticatedGetCommunicationListV1**](#inscriptionnotauthenticatedgetcommunicationlistv1) | **GET** /1/object/inscriptionnotauthenticated/{pkiInscriptionnotauthenticatedID}/getCommunicationList | Retrieve Communication list|
|[**inscriptionnotauthenticatedGetCommunicationrecipientsV1**](#inscriptionnotauthenticatedgetcommunicationrecipientsv1) | **GET** /1/object/inscriptionnotauthenticated/{pkiInscriptionnotauthenticatedID}/getCommunicationrecipients | Retrieve Inscriptionnotauthenticated\&#39;s Communicationrecipient|
|[**inscriptionnotauthenticatedGetCommunicationsendersV1**](#inscriptionnotauthenticatedgetcommunicationsendersv1) | **GET** /1/object/inscriptionnotauthenticated/{pkiInscriptionnotauthenticatedID}/getCommunicationsenders | Retrieve Inscriptionnotauthenticated\&#39;s Communicationsender|
|[**inscriptionnotauthenticatedGetInscriptionnotauthenticatedconditionsV1**](#inscriptionnotauthenticatedgetinscriptionnotauthenticatedconditionsv1) | **GET** /1/object/inscriptionnotauthenticated/{pkiInscriptionnotauthenticatedID}/getInscriptionnotauthenticatedconditions | Retrieve Inscriptionnotauthenticated conditions|
|[**inscriptionnotauthenticatedGetListV1**](#inscriptionnotauthenticatedgetlistv1) | **GET** /1/object/inscriptionnotauthenticated/getList | Retrieve Inscriptionnotauthenticated list|
|[**inscriptionnotauthenticatedGetObjectV2**](#inscriptionnotauthenticatedgetobjectv2) | **GET** /2/object/inscriptionnotauthenticated/{pkiInscriptionnotauthenticatedID} | Retrieve an existing Inscriptionnotauthenticated|
|[**inscriptionnotauthenticatedImportIntoEDMV1**](#inscriptionnotauthenticatedimportintoedmv1) | **POST** /1/object/inscriptionnotauthenticated/{pkiInscriptionnotauthenticatedID}/importIntoEDM | Import attachments into the Inscriptionnotauthenticated|

# **inscriptionnotauthenticatedFillInscriptionnotauthenticatedconditionV1**
> InscriptionnotauthenticatedFillInscriptionnotauthenticatedconditionV1Response inscriptionnotauthenticatedFillInscriptionnotauthenticatedconditionV1(inscriptionnotauthenticatedFillInscriptionnotauthenticatedconditionV1Request)



### Example

```typescript
import {
    ObjectInscriptionnotauthenticatedApi,
    Configuration,
    InscriptionnotauthenticatedFillInscriptionnotauthenticatedconditionV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptionnotauthenticatedApi(configuration);

let pkiInscriptionnotauthenticatedID: number; // (default to undefined)
let inscriptionnotauthenticatedFillInscriptionnotauthenticatedconditionV1Request: InscriptionnotauthenticatedFillInscriptionnotauthenticatedconditionV1Request; //

const { status, data } = await apiInstance.inscriptionnotauthenticatedFillInscriptionnotauthenticatedconditionV1(
    pkiInscriptionnotauthenticatedID,
    inscriptionnotauthenticatedFillInscriptionnotauthenticatedconditionV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **inscriptionnotauthenticatedFillInscriptionnotauthenticatedconditionV1Request** | **InscriptionnotauthenticatedFillInscriptionnotauthenticatedconditionV1Request**|  | |
| **pkiInscriptionnotauthenticatedID** | [**number**] |  | defaults to undefined|


### Return type

**InscriptionnotauthenticatedFillInscriptionnotauthenticatedconditionV1Response**

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

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **inscriptionnotauthenticatedGetCommunicationCountV1**
> InscriptionnotauthenticatedGetCommunicationCountV1Response inscriptionnotauthenticatedGetCommunicationCountV1()



### Example

```typescript
import {
    ObjectInscriptionnotauthenticatedApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptionnotauthenticatedApi(configuration);

let pkiInscriptionnotauthenticatedID: number; // (default to undefined)

const { status, data } = await apiInstance.inscriptionnotauthenticatedGetCommunicationCountV1(
    pkiInscriptionnotauthenticatedID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInscriptionnotauthenticatedID** | [**number**] |  | defaults to undefined|


### Return type

**InscriptionnotauthenticatedGetCommunicationCountV1Response**

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

# **inscriptionnotauthenticatedGetCommunicationListV1**
> InscriptionnotauthenticatedGetCommunicationListV1Response inscriptionnotauthenticatedGetCommunicationListV1()



### Example

```typescript
import {
    ObjectInscriptionnotauthenticatedApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptionnotauthenticatedApi(configuration);

let pkiInscriptionnotauthenticatedID: number; // (default to undefined)

const { status, data } = await apiInstance.inscriptionnotauthenticatedGetCommunicationListV1(
    pkiInscriptionnotauthenticatedID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInscriptionnotauthenticatedID** | [**number**] |  | defaults to undefined|


### Return type

**InscriptionnotauthenticatedGetCommunicationListV1Response**

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

# **inscriptionnotauthenticatedGetCommunicationrecipientsV1**
> InscriptionnotauthenticatedGetCommunicationrecipientsV1Response inscriptionnotauthenticatedGetCommunicationrecipientsV1()



### Example

```typescript
import {
    ObjectInscriptionnotauthenticatedApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptionnotauthenticatedApi(configuration);

let pkiInscriptionnotauthenticatedID: number; // (default to undefined)

const { status, data } = await apiInstance.inscriptionnotauthenticatedGetCommunicationrecipientsV1(
    pkiInscriptionnotauthenticatedID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInscriptionnotauthenticatedID** | [**number**] |  | defaults to undefined|


### Return type

**InscriptionnotauthenticatedGetCommunicationrecipientsV1Response**

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

# **inscriptionnotauthenticatedGetCommunicationsendersV1**
> InscriptionnotauthenticatedGetCommunicationsendersV1Response inscriptionnotauthenticatedGetCommunicationsendersV1()



### Example

```typescript
import {
    ObjectInscriptionnotauthenticatedApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptionnotauthenticatedApi(configuration);

let pkiInscriptionnotauthenticatedID: number; // (default to undefined)

const { status, data } = await apiInstance.inscriptionnotauthenticatedGetCommunicationsendersV1(
    pkiInscriptionnotauthenticatedID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInscriptionnotauthenticatedID** | [**number**] |  | defaults to undefined|


### Return type

**InscriptionnotauthenticatedGetCommunicationsendersV1Response**

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

# **inscriptionnotauthenticatedGetInscriptionnotauthenticatedconditionsV1**
> InscriptionnotauthenticatedGetInscriptionnotauthenticatedconditionsV1Response inscriptionnotauthenticatedGetInscriptionnotauthenticatedconditionsV1()



### Example

```typescript
import {
    ObjectInscriptionnotauthenticatedApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptionnotauthenticatedApi(configuration);

let pkiInscriptionnotauthenticatedID: number; // (default to undefined)

const { status, data } = await apiInstance.inscriptionnotauthenticatedGetInscriptionnotauthenticatedconditionsV1(
    pkiInscriptionnotauthenticatedID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInscriptionnotauthenticatedID** | [**number**] |  | defaults to undefined|


### Return type

**InscriptionnotauthenticatedGetInscriptionnotauthenticatedconditionsV1Response**

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

# **inscriptionnotauthenticatedGetListV1**
> InscriptionnotauthenticatedGetListV1Response inscriptionnotauthenticatedGetListV1()

Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eInscriptionStep | TemporaryNotAuthenticated<br>ImportedInscription<br>Inscription<br>ModifiedInscription<br>ContractEnded<br>ExpiredInscription<br>Out-market<br>ImportedNotauthenticated<br>NotAuthenticated<br>ModifiedNotauthenticated<br>Authenticated |

### Example

```typescript
import {
    ObjectInscriptionnotauthenticatedApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptionnotauthenticatedApi(configuration);

let eOrderBy: 'pkiInscriptionID_ASC' | 'pkiInscriptionID_DESC' | 'pkiInscriptionnotauthenticatedID_ASC' | 'pkiInscriptionnotauthenticatedID_DESC' | 'fkiInscriptiontypeID_ASC' | 'fkiInscriptiontypeID_DESC' | 'sInscriptiontypeNameX_ASC' | 'sInscriptiontypeNameX_DESC' | 'eInscriptionStep_ASC' | 'eInscriptionStep_DESC' | 'sInscriptionCivicend_ASC' | 'sInscriptionCivicend_DESC' | 'sInscriptionMLS_ASC' | 'sInscriptionMLS_DESC' | 'dInscriptionSaleprice_ASC' | 'dInscriptionSaleprice_DESC' | 'dInscriptionRentprice_ASC' | 'dInscriptionRentprice_DESC' | 'dtInscriptionDate_ASC' | 'dtInscriptionDate_DESC' | 'dtInscriptionExpirationdate_ASC' | 'dtInscriptionExpirationdate_DESC' | 'dtInscriptionNotarydate_ASC' | 'dtInscriptionNotarydate_DESC' | 'bInscriptionInspection_ASC' | 'bInscriptionInspection_DESC' | 'bInscriptionIsactive_ASC' | 'bInscriptionIsactive_DESC' | 'dtInscriptionnotauthenticatedNotaryscheduledate_ASC' | 'dtInscriptionnotauthenticatedNotaryscheduledate_DESC' | 'dtInscriptionnotauthenticatedTransactiondate_ASC' | 'dtInscriptionnotauthenticatedTransactiondate_DESC' | 'dtInscriptionnotauthenticatedTransactiondateReal_ASC' | 'dtInscriptionnotauthenticatedTransactiondateReal_DESC' | 'bInscriptionnotauthenticatedConditional_ASC' | 'bInscriptionnotauthenticatedConditional_DESC' | 'bInscriptionnotauthenticatedIsactive_ASC' | 'bInscriptionnotauthenticatedIsactive_DESC' | 'bInscriptionnotauthenticatedDraft_ASC' | 'bInscriptionnotauthenticatedDraft_DESC' | 'sAddressCivic_ASC' | 'sAddressCivic_DESC' | 'sAddressStreet_ASC' | 'sAddressStreet_DESC' | 'sAddressSuite_ASC' | 'sAddressSuite_DESC' | 'sAddressCity_ASC' | 'sAddressCity_DESC' | 'sAddressZip_ASC' | 'sAddressZip_DESC' | 'sProvinceNameX_ASC' | 'sProvinceNameX_DESC' | 'sCountryNameX_ASC' | 'sCountryNameX_DESC' | 'iInscriptionnotauthenticatedCanceled_ASC' | 'iInscriptionnotauthenticatedCanceled_DESC' | 'sInscriptionnotauthenticatedOffertopurchasenumber_ASC' | 'sInscriptionnotauthenticatedOffertopurchasenumber_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.inscriptionnotauthenticatedGetListV1(
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
| **eOrderBy** | [**&#39;pkiInscriptionID_ASC&#39; | &#39;pkiInscriptionID_DESC&#39; | &#39;pkiInscriptionnotauthenticatedID_ASC&#39; | &#39;pkiInscriptionnotauthenticatedID_DESC&#39; | &#39;fkiInscriptiontypeID_ASC&#39; | &#39;fkiInscriptiontypeID_DESC&#39; | &#39;sInscriptiontypeNameX_ASC&#39; | &#39;sInscriptiontypeNameX_DESC&#39; | &#39;eInscriptionStep_ASC&#39; | &#39;eInscriptionStep_DESC&#39; | &#39;sInscriptionCivicend_ASC&#39; | &#39;sInscriptionCivicend_DESC&#39; | &#39;sInscriptionMLS_ASC&#39; | &#39;sInscriptionMLS_DESC&#39; | &#39;dInscriptionSaleprice_ASC&#39; | &#39;dInscriptionSaleprice_DESC&#39; | &#39;dInscriptionRentprice_ASC&#39; | &#39;dInscriptionRentprice_DESC&#39; | &#39;dtInscriptionDate_ASC&#39; | &#39;dtInscriptionDate_DESC&#39; | &#39;dtInscriptionExpirationdate_ASC&#39; | &#39;dtInscriptionExpirationdate_DESC&#39; | &#39;dtInscriptionNotarydate_ASC&#39; | &#39;dtInscriptionNotarydate_DESC&#39; | &#39;bInscriptionInspection_ASC&#39; | &#39;bInscriptionInspection_DESC&#39; | &#39;bInscriptionIsactive_ASC&#39; | &#39;bInscriptionIsactive_DESC&#39; | &#39;dtInscriptionnotauthenticatedNotaryscheduledate_ASC&#39; | &#39;dtInscriptionnotauthenticatedNotaryscheduledate_DESC&#39; | &#39;dtInscriptionnotauthenticatedTransactiondate_ASC&#39; | &#39;dtInscriptionnotauthenticatedTransactiondate_DESC&#39; | &#39;dtInscriptionnotauthenticatedTransactiondateReal_ASC&#39; | &#39;dtInscriptionnotauthenticatedTransactiondateReal_DESC&#39; | &#39;bInscriptionnotauthenticatedConditional_ASC&#39; | &#39;bInscriptionnotauthenticatedConditional_DESC&#39; | &#39;bInscriptionnotauthenticatedIsactive_ASC&#39; | &#39;bInscriptionnotauthenticatedIsactive_DESC&#39; | &#39;bInscriptionnotauthenticatedDraft_ASC&#39; | &#39;bInscriptionnotauthenticatedDraft_DESC&#39; | &#39;sAddressCivic_ASC&#39; | &#39;sAddressCivic_DESC&#39; | &#39;sAddressStreet_ASC&#39; | &#39;sAddressStreet_DESC&#39; | &#39;sAddressSuite_ASC&#39; | &#39;sAddressSuite_DESC&#39; | &#39;sAddressCity_ASC&#39; | &#39;sAddressCity_DESC&#39; | &#39;sAddressZip_ASC&#39; | &#39;sAddressZip_DESC&#39; | &#39;sProvinceNameX_ASC&#39; | &#39;sProvinceNameX_DESC&#39; | &#39;sCountryNameX_ASC&#39; | &#39;sCountryNameX_DESC&#39; | &#39;iInscriptionnotauthenticatedCanceled_ASC&#39; | &#39;iInscriptionnotauthenticatedCanceled_DESC&#39; | &#39;sInscriptionnotauthenticatedOffertopurchasenumber_ASC&#39; | &#39;sInscriptionnotauthenticatedOffertopurchasenumber_DESC&#39;**]**Array<&#39;pkiInscriptionID_ASC&#39; &#124; &#39;pkiInscriptionID_DESC&#39; &#124; &#39;pkiInscriptionnotauthenticatedID_ASC&#39; &#124; &#39;pkiInscriptionnotauthenticatedID_DESC&#39; &#124; &#39;fkiInscriptiontypeID_ASC&#39; &#124; &#39;fkiInscriptiontypeID_DESC&#39; &#124; &#39;sInscriptiontypeNameX_ASC&#39; &#124; &#39;sInscriptiontypeNameX_DESC&#39; &#124; &#39;eInscriptionStep_ASC&#39; &#124; &#39;eInscriptionStep_DESC&#39; &#124; &#39;sInscriptionCivicend_ASC&#39; &#124; &#39;sInscriptionCivicend_DESC&#39; &#124; &#39;sInscriptionMLS_ASC&#39; &#124; &#39;sInscriptionMLS_DESC&#39; &#124; &#39;dInscriptionSaleprice_ASC&#39; &#124; &#39;dInscriptionSaleprice_DESC&#39; &#124; &#39;dInscriptionRentprice_ASC&#39; &#124; &#39;dInscriptionRentprice_DESC&#39; &#124; &#39;dtInscriptionDate_ASC&#39; &#124; &#39;dtInscriptionDate_DESC&#39; &#124; &#39;dtInscriptionExpirationdate_ASC&#39; &#124; &#39;dtInscriptionExpirationdate_DESC&#39; &#124; &#39;dtInscriptionNotarydate_ASC&#39; &#124; &#39;dtInscriptionNotarydate_DESC&#39; &#124; &#39;bInscriptionInspection_ASC&#39; &#124; &#39;bInscriptionInspection_DESC&#39; &#124; &#39;bInscriptionIsactive_ASC&#39; &#124; &#39;bInscriptionIsactive_DESC&#39; &#124; &#39;dtInscriptionnotauthenticatedNotaryscheduledate_ASC&#39; &#124; &#39;dtInscriptionnotauthenticatedNotaryscheduledate_DESC&#39; &#124; &#39;dtInscriptionnotauthenticatedTransactiondate_ASC&#39; &#124; &#39;dtInscriptionnotauthenticatedTransactiondate_DESC&#39; &#124; &#39;dtInscriptionnotauthenticatedTransactiondateReal_ASC&#39; &#124; &#39;dtInscriptionnotauthenticatedTransactiondateReal_DESC&#39; &#124; &#39;bInscriptionnotauthenticatedConditional_ASC&#39; &#124; &#39;bInscriptionnotauthenticatedConditional_DESC&#39; &#124; &#39;bInscriptionnotauthenticatedIsactive_ASC&#39; &#124; &#39;bInscriptionnotauthenticatedIsactive_DESC&#39; &#124; &#39;bInscriptionnotauthenticatedDraft_ASC&#39; &#124; &#39;bInscriptionnotauthenticatedDraft_DESC&#39; &#124; &#39;sAddressCivic_ASC&#39; &#124; &#39;sAddressCivic_DESC&#39; &#124; &#39;sAddressStreet_ASC&#39; &#124; &#39;sAddressStreet_DESC&#39; &#124; &#39;sAddressSuite_ASC&#39; &#124; &#39;sAddressSuite_DESC&#39; &#124; &#39;sAddressCity_ASC&#39; &#124; &#39;sAddressCity_DESC&#39; &#124; &#39;sAddressZip_ASC&#39; &#124; &#39;sAddressZip_DESC&#39; &#124; &#39;sProvinceNameX_ASC&#39; &#124; &#39;sProvinceNameX_DESC&#39; &#124; &#39;sCountryNameX_ASC&#39; &#124; &#39;sCountryNameX_DESC&#39; &#124; &#39;iInscriptionnotauthenticatedCanceled_ASC&#39; &#124; &#39;iInscriptionnotauthenticatedCanceled_DESC&#39; &#124; &#39;sInscriptionnotauthenticatedOffertopurchasenumber_ASC&#39; &#124; &#39;sInscriptionnotauthenticatedOffertopurchasenumber_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**InscriptionnotauthenticatedGetListV1Response**

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

# **inscriptionnotauthenticatedGetObjectV2**
> InscriptionnotauthenticatedGetObjectV2Response inscriptionnotauthenticatedGetObjectV2()



### Example

```typescript
import {
    ObjectInscriptionnotauthenticatedApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptionnotauthenticatedApi(configuration);

let pkiInscriptionnotauthenticatedID: number; //The unique ID of the Inscriptionnotauthenticated (default to undefined)

const { status, data } = await apiInstance.inscriptionnotauthenticatedGetObjectV2(
    pkiInscriptionnotauthenticatedID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInscriptionnotauthenticatedID** | [**number**] | The unique ID of the Inscriptionnotauthenticated | defaults to undefined|


### Return type

**InscriptionnotauthenticatedGetObjectV2Response**

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

# **inscriptionnotauthenticatedImportIntoEDMV1**
> InscriptionnotauthenticatedImportIntoEDMV1Response inscriptionnotauthenticatedImportIntoEDMV1(inscriptionnotauthenticatedImportIntoEDMV1Request)



### Example

```typescript
import {
    ObjectInscriptionnotauthenticatedApi,
    Configuration,
    InscriptionnotauthenticatedImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInscriptionnotauthenticatedApi(configuration);

let pkiInscriptionnotauthenticatedID: number; // (default to undefined)
let inscriptionnotauthenticatedImportIntoEDMV1Request: InscriptionnotauthenticatedImportIntoEDMV1Request; //

const { status, data } = await apiInstance.inscriptionnotauthenticatedImportIntoEDMV1(
    pkiInscriptionnotauthenticatedID,
    inscriptionnotauthenticatedImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **inscriptionnotauthenticatedImportIntoEDMV1Request** | **InscriptionnotauthenticatedImportIntoEDMV1Request**|  | |
| **pkiInscriptionnotauthenticatedID** | [**number**] |  | defaults to undefined|


### Return type

**InscriptionnotauthenticatedImportIntoEDMV1Response**

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

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

