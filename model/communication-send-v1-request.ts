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
import type { CommunicationRequestCompound } from './communication-request-compound';

/**
 * Request for POST /1/object/communication
 * @export
 * @interface CommunicationSendV1Request
 */
export interface CommunicationSendV1Request {
    /**
     * 
     * @type {Array<CommunicationRequestCompound>}
     * @memberof CommunicationSendV1Request
     */
    /*'a_objCommunication': Array<CommunicationRequestCompound>;*/
    'a_objCommunication': Array<CommunicationRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A CommunicationSendV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommunicationSendV1Request
 */
export class DataObjectCommunicationSendV1Request {
   a_objCommunication:Array<CommunicationRequestCompound> = []
}

/**
 * @export 
 * A CommunicationSendV1Request Validation Object
 * @class ValidationObjectCommunicationSendV1Request
 */
export class ValidationObjectCommunicationSendV1Request {
   a_objCommunication = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


