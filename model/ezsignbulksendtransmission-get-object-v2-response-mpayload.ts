/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksendtransmissionResponseCompound } from './ezsignbulksendtransmission-response-compound';

/**
 * Payload for GET /2/object/ezsignbulksendtransmission/{pkiEzsignbulksendtransmissionID}
 * @export
 * @interface EzsignbulksendtransmissionGetObjectV2ResponseMPayload
 */
export interface EzsignbulksendtransmissionGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {EzsignbulksendtransmissionResponseCompound}
     * @memberof EzsignbulksendtransmissionGetObjectV2ResponseMPayload
     */
    /*'objEzsignbulksendtransmission': EzsignbulksendtransmissionResponseCompound;*/
    'objEzsignbulksendtransmission': EzsignbulksendtransmissionResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignbulksendtransmissionResponseCompound } from './'
// @ts-ignore
import { ValidationObjectEzsignbulksendtransmissionResponseCompound } from './'

/**
 * @export 
 * A EzsignbulksendtransmissionGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignbulksendtransmissionGetObjectV2ResponseMPayload
 */
export class DataObjectEzsignbulksendtransmissionGetObjectV2ResponseMPayload {
   objEzsignbulksendtransmission:EzsignbulksendtransmissionResponseCompound = new DataObjectEzsignbulksendtransmissionResponseCompound()
}

/**
 * @export 
 * A EzsignbulksendtransmissionGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectEzsignbulksendtransmissionGetObjectV2ResponseMPayload
 */
export class ValidationObjectEzsignbulksendtransmissionGetObjectV2ResponseMPayload {
   objEzsignbulksendtransmission = new ValidationObjectEzsignbulksendtransmissionResponseCompound()
} 


