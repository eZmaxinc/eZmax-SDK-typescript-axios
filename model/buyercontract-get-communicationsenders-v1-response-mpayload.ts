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
 * Response for GET /1/object/buyercontract/{pkiBuyercontractID}/getCommunicationsenders
 * @export
 * @interface BuyercontractGetCommunicationsendersV1ResponseMPayload
 */
export interface BuyercontractGetCommunicationsendersV1ResponseMPayload {
    /**
     * 
     * @type {Array<CustomCommunicationsenderResponse>}
     * @memberof BuyercontractGetCommunicationsendersV1ResponseMPayload
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
 * A BuyercontractGetCommunicationsendersV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectBuyercontractGetCommunicationsendersV1ResponseMPayload
 */
export class DataObjectBuyercontractGetCommunicationsendersV1ResponseMPayload {
   a_objCommunicationsenders:Array<CustomCommunicationsenderResponse> = []
}

/**
 * @export 
 * A BuyercontractGetCommunicationsendersV1ResponseMPayload Validation Object
 * @class ValidationObjectBuyercontractGetCommunicationsendersV1ResponseMPayload
 */
export class ValidationObjectBuyercontractGetCommunicationsendersV1ResponseMPayload {
   a_objCommunicationsenders = {
      type: 'array',
      required: true
   }
} 


