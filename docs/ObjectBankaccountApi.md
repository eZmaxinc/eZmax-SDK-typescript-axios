# ObjectBankaccountApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**bankaccountBatchDownloadV1**](#bankaccountbatchdownloadv1) | **POST** /1/object/bankaccount/{pkiBankaccountID}/batchDownload | Download multiples attachments from a Bankaccount|
|[**bankaccountGetAttachmentsV1**](#bankaccountgetattachmentsv1) | **GET** /1/object/bankaccount/{pkiBankaccountID}/getAttachments | Retrieve Bankaccount\&#39;s attachments|
|[**bankaccountGetAutocompleteV2**](#bankaccountgetautocompletev2) | **GET** /2/object/bankaccount/getAutocomplete/{sSelector} | Retrieve Bankaccounts and IDs|
|[**bankaccountGetCommunicationCountV1**](#bankaccountgetcommunicationcountv1) | **GET** /1/object/bankaccount/{pkiBankaccountID}/getCommunicationCount | Retrieve Communication count|
|[**bankaccountGetCommunicationListV1**](#bankaccountgetcommunicationlistv1) | **GET** /1/object/bankaccount/{pkiBankaccountID}/getCommunicationList | Retrieve Communication list|
|[**bankaccountGetCommunicationrecipientsV1**](#bankaccountgetcommunicationrecipientsv1) | **GET** /1/object/bankaccount/{pkiBankaccountID}/getCommunicationrecipients | Retrieve Communication recipients|
|[**bankaccountGetCommunicationsendersV1**](#bankaccountgetcommunicationsendersv1) | **GET** /1/object/bankaccount/{pkiBankaccountID}/getCommunicationsenders | Retrieve Communication senders|
|[**bankaccountGetListV1**](#bankaccountgetlistv1) | **GET** /1/object/bankaccount/getList | Retrieve Bankaccount list|
|[**bankaccountImportIntoEDMV1**](#bankaccountimportintoedmv1) | **POST** /1/object/bankaccount/{pkiBankaccountID}/importIntoEDM | Import attachments into the Bankaccount|

# **bankaccountBatchDownloadV1**
> File bankaccountBatchDownloadV1(bankaccountBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectBankaccountApi,
    Configuration,
    BankaccountBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBankaccountApi(configuration);

let pkiBankaccountID: number; // (default to undefined)
let bankaccountBatchDownloadV1Request: BankaccountBatchDownloadV1Request; //

const { status, data } = await apiInstance.bankaccountBatchDownloadV1(
    pkiBankaccountID,
    bankaccountBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **bankaccountBatchDownloadV1Request** | **BankaccountBatchDownloadV1Request**|  | |
| **pkiBankaccountID** | [**number**] |  | defaults to undefined|


### Return type

**File**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/zip, text/xml, application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **bankaccountGetAttachmentsV1**
> BankaccountGetAttachmentsV1Response bankaccountGetAttachmentsV1()


### Example

```typescript
import {
    ObjectBankaccountApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBankaccountApi(configuration);

let pkiBankaccountID: number; // (default to undefined)

const { status, data } = await apiInstance.bankaccountGetAttachmentsV1(
    pkiBankaccountID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiBankaccountID** | [**number**] |  | defaults to undefined|


### Return type

**BankaccountGetAttachmentsV1Response**

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

# **bankaccountGetAutocompleteV2**
> BankaccountGetAutocompleteV2Response bankaccountGetAutocompleteV2()

Get the list of Bankaccount to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectBankaccountApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBankaccountApi(configuration);

let sSelector: 'All'; //The type of Bankaccounts to return (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)

const { status, data } = await apiInstance.bankaccountGetAutocompleteV2(
    sSelector,
    eFilterActive,
    sQuery,
    acceptLanguage
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;All&#39;**]**Array<&#39;All&#39;>** | The type of Bankaccounts to return | defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|


### Return type

**BankaccountGetAutocompleteV2Response**

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

# **bankaccountGetCommunicationCountV1**
> BankaccountGetCommunicationCountV1Response bankaccountGetCommunicationCountV1()


### Example

```typescript
import {
    ObjectBankaccountApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBankaccountApi(configuration);

let pkiBankaccountID: number; // (default to undefined)

const { status, data } = await apiInstance.bankaccountGetCommunicationCountV1(
    pkiBankaccountID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiBankaccountID** | [**number**] |  | defaults to undefined|


### Return type

**BankaccountGetCommunicationCountV1Response**

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

# **bankaccountGetCommunicationListV1**
> BankaccountGetCommunicationListV1Response bankaccountGetCommunicationListV1()


### Example

```typescript
import {
    ObjectBankaccountApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBankaccountApi(configuration);

let pkiBankaccountID: number; // (default to undefined)

const { status, data } = await apiInstance.bankaccountGetCommunicationListV1(
    pkiBankaccountID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiBankaccountID** | [**number**] |  | defaults to undefined|


### Return type

**BankaccountGetCommunicationListV1Response**

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

# **bankaccountGetCommunicationrecipientsV1**
> BankaccountGetCommunicationrecipientsV1Response bankaccountGetCommunicationrecipientsV1()


### Example

```typescript
import {
    ObjectBankaccountApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBankaccountApi(configuration);

let pkiBankaccountID: number; // (default to undefined)

const { status, data } = await apiInstance.bankaccountGetCommunicationrecipientsV1(
    pkiBankaccountID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiBankaccountID** | [**number**] |  | defaults to undefined|


### Return type

**BankaccountGetCommunicationrecipientsV1Response**

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

# **bankaccountGetCommunicationsendersV1**
> BankaccountGetCommunicationsendersV1Response bankaccountGetCommunicationsendersV1()


### Example

```typescript
import {
    ObjectBankaccountApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBankaccountApi(configuration);

let pkiBankaccountID: number; // (default to undefined)

const { status, data } = await apiInstance.bankaccountGetCommunicationsendersV1(
    pkiBankaccountID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiBankaccountID** | [**number**] |  | defaults to undefined|


### Return type

**BankaccountGetCommunicationsendersV1Response**

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

# **bankaccountGetListV1**
> BankaccountGetListV1Response bankaccountGetListV1()

Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eBankaccountType | Chequing<br>Trust |

### Example

```typescript
import {
    ObjectBankaccountApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBankaccountApi(configuration);

let eOrderBy: 'pkiBankaccountID_ASC' | 'pkiBankaccountID_DESC' | 'sBankaccountBankname_ASC' | 'sBankaccountBankname_DESC' | 'sBankaccountTransit_ASC' | 'sBankaccountTransit_DESC' | 'sBankaccountInstitution_ASC' | 'sBankaccountInstitution_DESC' | 'sBankaccountAccount_ASC' | 'sBankaccountAccount_DESC' | 'sBankaccountNumber_ASC' | 'sBankaccountNumber_DESC' | 'eBankaccountType_ASC' | 'eBankaccountType_DESC' | 'bBankaccountCommissionprocessing_ASC' | 'bBankaccountCommissionprocessing_DESC' | 'bBankaccountIsactive_ASC' | 'bBankaccountIsactive_DESC' | 'iGlaccountCode_ASC' | 'iGlaccountCode_DESC' | 'sGlaccountDescriptionX_ASC' | 'sGlaccountDescriptionX_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.bankaccountGetListV1(
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
| **eOrderBy** | [**&#39;pkiBankaccountID_ASC&#39; | &#39;pkiBankaccountID_DESC&#39; | &#39;sBankaccountBankname_ASC&#39; | &#39;sBankaccountBankname_DESC&#39; | &#39;sBankaccountTransit_ASC&#39; | &#39;sBankaccountTransit_DESC&#39; | &#39;sBankaccountInstitution_ASC&#39; | &#39;sBankaccountInstitution_DESC&#39; | &#39;sBankaccountAccount_ASC&#39; | &#39;sBankaccountAccount_DESC&#39; | &#39;sBankaccountNumber_ASC&#39; | &#39;sBankaccountNumber_DESC&#39; | &#39;eBankaccountType_ASC&#39; | &#39;eBankaccountType_DESC&#39; | &#39;bBankaccountCommissionprocessing_ASC&#39; | &#39;bBankaccountCommissionprocessing_DESC&#39; | &#39;bBankaccountIsactive_ASC&#39; | &#39;bBankaccountIsactive_DESC&#39; | &#39;iGlaccountCode_ASC&#39; | &#39;iGlaccountCode_DESC&#39; | &#39;sGlaccountDescriptionX_ASC&#39; | &#39;sGlaccountDescriptionX_DESC&#39;**]**Array<&#39;pkiBankaccountID_ASC&#39; &#124; &#39;pkiBankaccountID_DESC&#39; &#124; &#39;sBankaccountBankname_ASC&#39; &#124; &#39;sBankaccountBankname_DESC&#39; &#124; &#39;sBankaccountTransit_ASC&#39; &#124; &#39;sBankaccountTransit_DESC&#39; &#124; &#39;sBankaccountInstitution_ASC&#39; &#124; &#39;sBankaccountInstitution_DESC&#39; &#124; &#39;sBankaccountAccount_ASC&#39; &#124; &#39;sBankaccountAccount_DESC&#39; &#124; &#39;sBankaccountNumber_ASC&#39; &#124; &#39;sBankaccountNumber_DESC&#39; &#124; &#39;eBankaccountType_ASC&#39; &#124; &#39;eBankaccountType_DESC&#39; &#124; &#39;bBankaccountCommissionprocessing_ASC&#39; &#124; &#39;bBankaccountCommissionprocessing_DESC&#39; &#124; &#39;bBankaccountIsactive_ASC&#39; &#124; &#39;bBankaccountIsactive_DESC&#39; &#124; &#39;iGlaccountCode_ASC&#39; &#124; &#39;iGlaccountCode_DESC&#39; &#124; &#39;sGlaccountDescriptionX_ASC&#39; &#124; &#39;sGlaccountDescriptionX_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**BankaccountGetListV1Response**

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

# **bankaccountImportIntoEDMV1**
> BankaccountImportIntoEDMV1Response bankaccountImportIntoEDMV1(bankaccountImportIntoEDMV1Request)


### Example

```typescript
import {
    ObjectBankaccountApi,
    Configuration,
    BankaccountImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectBankaccountApi(configuration);

let pkiBankaccountID: number; // (default to undefined)
let bankaccountImportIntoEDMV1Request: BankaccountImportIntoEDMV1Request; //

const { status, data } = await apiInstance.bankaccountImportIntoEDMV1(
    pkiBankaccountID,
    bankaccountImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **bankaccountImportIntoEDMV1Request** | **BankaccountImportIntoEDMV1Request**|  | |
| **pkiBankaccountID** | [**number**] |  | defaults to undefined|


### Return type

**BankaccountImportIntoEDMV1Response**

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

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

