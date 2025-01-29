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
import type { CustomCommunicationrecipientsrecipientResponse } from './custom-communicationrecipientsrecipient-response';

/**
 * Generic CommunicationrecipientsGroup Response
 * @export
 * @interface CustomCommunicationrecipientsgroupResponse
 */
export interface CustomCommunicationrecipientsgroupResponse {
    /**
     * The label for the Communicationrecipientsgroup
     * @type {string}
     * @memberof CustomCommunicationrecipientsgroupResponse
     */
    /*'sCommunicationrecipientsgroupLabel': string;*/
    'sCommunicationrecipientsgroupLabel': string;
    /**
     * 
     * @type {Array<CustomCommunicationrecipientsrecipientResponse>}
     * @memberof CustomCommunicationrecipientsgroupResponse
     */
    /*'a_objCommunicationrecipientsrecipient': Array<CustomCommunicationrecipientsrecipientResponse>;*/
    'a_objCommunicationrecipientsrecipient': Array<CustomCommunicationrecipientsrecipientResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CustomCommunicationrecipientsgroupResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCustomCommunicationrecipientsgroupResponse
 */
export class DataObjectCustomCommunicationrecipientsgroupResponse {
   sCommunicationrecipientsgroupLabel:string = ''
   a_objCommunicationrecipientsrecipient:Array<CustomCommunicationrecipientsrecipientResponse> = []
}

/**
 * @export 
 * A CustomCommunicationrecipientsgroupResponse Validation Object
 * @class ValidationObjectCustomCommunicationrecipientsgroupResponse
 */
export class ValidationObjectCustomCommunicationrecipientsgroupResponse {
   sCommunicationrecipientsgroupLabel = {
      type: 'string',
      required: true
   }
   a_objCommunicationrecipientsrecipient = {
      type: 'array',
      required: true
   }
} 


