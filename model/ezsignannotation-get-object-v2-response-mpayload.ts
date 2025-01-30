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
import type { EzsignannotationResponseCompound } from './ezsignannotation-response-compound';

/**
 * Payload for GET /2/object/ezsignannotation/{pkiEzsignannotationID}
 * @export
 * @interface EzsignannotationGetObjectV2ResponseMPayload
 */
export interface EzsignannotationGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {EzsignannotationResponseCompound}
     * @memberof EzsignannotationGetObjectV2ResponseMPayload
     */
    /*'objEzsignannotation': EzsignannotationResponseCompound;*/
    'objEzsignannotation': EzsignannotationResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsignannotationResponseCompound } from './'
// @ts-ignore
import { ValidationObjectEzsignannotationResponseCompound } from './'

/**
 * @export 
 * A EzsignannotationGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignannotationGetObjectV2ResponseMPayload
 */
export class DataObjectEzsignannotationGetObjectV2ResponseMPayload {
   objEzsignannotation:EzsignannotationResponseCompound = new DataObjectEzsignannotationResponseCompound()
}

/**
 * @export 
 * A EzsignannotationGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectEzsignannotationGetObjectV2ResponseMPayload
 */
export class ValidationObjectEzsignannotationGetObjectV2ResponseMPayload {
   objEzsignannotation = new ValidationObjectEzsignannotationResponseCompound()
} 


