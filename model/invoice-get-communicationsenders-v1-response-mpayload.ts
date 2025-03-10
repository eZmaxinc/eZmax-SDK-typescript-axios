/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { CustomCommunicationsenderResponse } from './custom-communicationsender-response';

/**
 * Response for GET /1/object/invoice/{pkiInvoiceID}/getCommunicationsenders
 * @export
 * @interface InvoiceGetCommunicationsendersV1ResponseMPayload
 */
export interface InvoiceGetCommunicationsendersV1ResponseMPayload {
    /**
     * 
     * @type {Array<CustomCommunicationsenderResponse>}
     * @memberof InvoiceGetCommunicationsendersV1ResponseMPayload
     */
    /*'a_objCommunicationsenders': Array<CustomCommunicationsenderResponse>;*/
    'a_objCommunicationsenders': Array<CustomCommunicationsenderResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A InvoiceGetCommunicationsendersV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectInvoiceGetCommunicationsendersV1ResponseMPayload
 */
export class DataObjectInvoiceGetCommunicationsendersV1ResponseMPayload {
   a_objCommunicationsenders:Array<CustomCommunicationsenderResponse> = []
}

/**
 * @export 
 * A InvoiceGetCommunicationsendersV1ResponseMPayload Validation Object
 * @class ValidationObjectInvoiceGetCommunicationsendersV1ResponseMPayload
 */
export class ValidationObjectInvoiceGetCommunicationsendersV1ResponseMPayload {
   a_objCommunicationsenders = {
      type: 'array',
      required: true
   }
} 


