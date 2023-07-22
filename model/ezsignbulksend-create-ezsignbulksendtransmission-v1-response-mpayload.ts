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
import { EzsignbulksendtransmissionResponse } from './ezsignbulksendtransmission-response';

/**
 * Payload for POST /1/object/ezsignbulksend/{pkiEzsignbulksendID}/createEzsignbulksendtransmission
 * @export
 * @interface EzsignbulksendCreateEzsignbulksendtransmissionV1ResponseMPayload
 */
export interface EzsignbulksendCreateEzsignbulksendtransmissionV1ResponseMPayload {
    /**
     * 
     * @type {EzsignbulksendtransmissionResponse}
     * @memberof EzsignbulksendCreateEzsignbulksendtransmissionV1ResponseMPayload
     */
    'objEzsignbulksendtransmission': EzsignbulksendtransmissionResponse;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignbulksendtransmissionResponse } from './'
// @ts-ignore
import { ValidationObjectEzsignbulksendtransmissionResponse } from './'

/**
 * @export 
 * A EzsignbulksendCreateEzsignbulksendtransmissionV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendCreateEzsignbulksendtransmissionV1ResponseMPayload
 */
export class DataObjectEzsignbulksendCreateEzsignbulksendtransmissionV1ResponseMPayload {
   objEzsignbulksendtransmission:EzsignbulksendtransmissionResponse = new DataObjectEzsignbulksendtransmissionResponse()
}

/**
 * @export 
 * A EzsignbulksendCreateEzsignbulksendtransmissionV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsignbulksendCreateEzsignbulksendtransmissionV1ResponseMPayload
 */
export class ValidationObjectEzsignbulksendCreateEzsignbulksendtransmissionV1ResponseMPayload {
   objEzsignbulksendtransmission = new ValidationObjectEzsignbulksendtransmissionResponse()
} 


