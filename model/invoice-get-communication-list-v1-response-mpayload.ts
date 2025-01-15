/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { CustomCommunicationListElementResponse } from './custom-communication-list-element-response';

/**
 * Response for GET /1/object/invoice/{pkiInvoiceID}/getCommunicationList
 * @export
 * @interface InvoiceGetCommunicationListV1ResponseMPayload
 */
export interface InvoiceGetCommunicationListV1ResponseMPayload {
    /**
     * 
     * @type {Array<CustomCommunicationListElementResponse>}
     * @memberof InvoiceGetCommunicationListV1ResponseMPayload
     */
    /*'a_objCommunication': Array<CustomCommunicationListElementResponse>;*/
    'a_objCommunication': Array<CustomCommunicationListElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A InvoiceGetCommunicationListV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectInvoiceGetCommunicationListV1ResponseMPayload
 */
export class DataObjectInvoiceGetCommunicationListV1ResponseMPayload {
   a_objCommunication:Array<CustomCommunicationListElementResponse> = []
}

/**
 * @export 
 * A InvoiceGetCommunicationListV1ResponseMPayload Validation Object
 * @class ValidationObjectInvoiceGetCommunicationListV1ResponseMPayload
 */
export class ValidationObjectInvoiceGetCommunicationListV1ResponseMPayload {
   a_objCommunication = {
      type: 'array',
      required: true
   }
} 


