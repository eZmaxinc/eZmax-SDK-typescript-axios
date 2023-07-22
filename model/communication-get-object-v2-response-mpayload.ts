/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommunicationResponseCompound } from './communication-response-compound';

/**
 * Payload for GET /2/object/communication/{pkiCommunicationID}
 * @export
 * @interface CommunicationGetObjectV2ResponseMPayload
 */
export interface CommunicationGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {CommunicationResponseCompound}
     * @memberof CommunicationGetObjectV2ResponseMPayload
     */
    'objCommunication': CommunicationResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommunicationResponseCompound } from './'
// @ts-ignore
import { ValidationObjectCommunicationResponseCompound } from './'

/**
 * @export 
 * A CommunicationGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommunicationGetObjectV2ResponseMPayload
 */
export class DataObjectCommunicationGetObjectV2ResponseMPayload {
   objCommunication:CommunicationResponseCompound = new DataObjectCommunicationResponseCompound()
}

/**
 * @export 
 * A CommunicationGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectCommunicationGetObjectV2ResponseMPayload
 */
export class ValidationObjectCommunicationGetObjectV2ResponseMPayload {
   objCommunication = new ValidationObjectCommunicationResponseCompound()
} 


