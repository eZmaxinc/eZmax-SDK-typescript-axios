# ObjectInvoiceApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**invoiceGetAttachmentsV1**](#invoicegetattachmentsv1) | **GET** /1/object/invoice/{pkiInvoiceID}/getAttachments | Retrieve Invoice\&#39;s Attachments|
|[**invoiceGetCommunicationCountV1**](#invoicegetcommunicationcountv1) | **GET** /1/object/invoice/{pkiInvoiceID}/getCommunicationCount | Retrieve Communication count|
|[**invoiceGetCommunicationListV1**](#invoicegetcommunicationlistv1) | **GET** /1/object/invoice/{pkiInvoiceID}/getCommunicationList | Retrieve Communication list|
|[**invoiceGetCommunicationrecipientsV1**](#invoicegetcommunicationrecipientsv1) | **GET** /1/object/invoice/{pkiInvoiceID}/getCommunicationrecipients | Retrieve Invoice\&#39;s Communicationrecipient|
|[**invoiceGetCommunicationsendersV1**](#invoicegetcommunicationsendersv1) | **GET** /1/object/invoice/{pkiInvoiceID}/getCommunicationsenders | Retrieve Invoice\&#39;s Communicationsender|
|[**invoiceImportIntoEDMV1**](#invoiceimportintoedmv1) | **POST** /1/object/invoice/{pkiInvoiceID}/importIntoEDM | Import attachments into the Invoice|

# **invoiceGetAttachmentsV1**
> InvoiceGetAttachmentsV1Response invoiceGetAttachmentsV1()



### Example

```typescript
import {
    ObjectInvoiceApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInvoiceApi(configuration);

let pkiInvoiceID: number; // (default to undefined)

const { status, data } = await apiInstance.invoiceGetAttachmentsV1(
    pkiInvoiceID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInvoiceID** | [**number**] |  | defaults to undefined|


### Return type

**InvoiceGetAttachmentsV1Response**

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

# **invoiceGetCommunicationCountV1**
> InvoiceGetCommunicationCountV1Response invoiceGetCommunicationCountV1()



### Example

```typescript
import {
    ObjectInvoiceApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInvoiceApi(configuration);

let pkiInvoiceID: number; // (default to undefined)

const { status, data } = await apiInstance.invoiceGetCommunicationCountV1(
    pkiInvoiceID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInvoiceID** | [**number**] |  | defaults to undefined|


### Return type

**InvoiceGetCommunicationCountV1Response**

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

# **invoiceGetCommunicationListV1**
> InvoiceGetCommunicationListV1Response invoiceGetCommunicationListV1()



### Example

```typescript
import {
    ObjectInvoiceApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInvoiceApi(configuration);

let pkiInvoiceID: number; // (default to undefined)

const { status, data } = await apiInstance.invoiceGetCommunicationListV1(
    pkiInvoiceID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInvoiceID** | [**number**] |  | defaults to undefined|


### Return type

**InvoiceGetCommunicationListV1Response**

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

# **invoiceGetCommunicationrecipientsV1**
> InvoiceGetCommunicationrecipientsV1Response invoiceGetCommunicationrecipientsV1()



### Example

```typescript
import {
    ObjectInvoiceApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInvoiceApi(configuration);

let pkiInvoiceID: number; // (default to undefined)

const { status, data } = await apiInstance.invoiceGetCommunicationrecipientsV1(
    pkiInvoiceID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInvoiceID** | [**number**] |  | defaults to undefined|


### Return type

**InvoiceGetCommunicationrecipientsV1Response**

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

# **invoiceGetCommunicationsendersV1**
> InvoiceGetCommunicationsendersV1Response invoiceGetCommunicationsendersV1()



### Example

```typescript
import {
    ObjectInvoiceApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInvoiceApi(configuration);

let pkiInvoiceID: number; // (default to undefined)

const { status, data } = await apiInstance.invoiceGetCommunicationsendersV1(
    pkiInvoiceID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiInvoiceID** | [**number**] |  | defaults to undefined|


### Return type

**InvoiceGetCommunicationsendersV1Response**

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

# **invoiceImportIntoEDMV1**
> InvoiceImportIntoEDMV1Response invoiceImportIntoEDMV1(invoiceImportIntoEDMV1Request)



### Example

```typescript
import {
    ObjectInvoiceApi,
    Configuration,
    InvoiceImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectInvoiceApi(configuration);

let pkiInvoiceID: number; // (default to undefined)
let invoiceImportIntoEDMV1Request: InvoiceImportIntoEDMV1Request; //

const { status, data } = await apiInstance.invoiceImportIntoEDMV1(
    pkiInvoiceID,
    invoiceImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **invoiceImportIntoEDMV1Request** | **InvoiceImportIntoEDMV1Request**|  | |
| **pkiInvoiceID** | [**number**] |  | defaults to undefined|


### Return type

**InvoiceImportIntoEDMV1Response**

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

