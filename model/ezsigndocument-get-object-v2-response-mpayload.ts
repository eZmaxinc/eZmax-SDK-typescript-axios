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
import type { EzsigndocumentResponseCompound } from './ezsigndocument-response-compound';

/**
 * Payload for GET /2/object/ezsigndocument/{pkiEzsigndocumentID}
 * @export
 * @interface EzsigndocumentGetObjectV2ResponseMPayload
 */
export interface EzsigndocumentGetObjectV2ResponseMPayload {
    /**
     * 
     * @type {EzsigndocumentResponseCompound}
     * @memberof EzsigndocumentGetObjectV2ResponseMPayload
     */
    /*'objEzsigndocument': EzsigndocumentResponseCompound;*/
    'objEzsigndocument': EzsigndocumentResponseCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigndocumentResponseCompound } from './'
// @ts-ignore
import { ValidationObjectEzsigndocumentResponseCompound } from './'

/**
 * @export 
 * A EzsigndocumentGetObjectV2ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentGetObjectV2ResponseMPayload
 */
export class DataObjectEzsigndocumentGetObjectV2ResponseMPayload {
   objEzsigndocument:EzsigndocumentResponseCompound = new DataObjectEzsigndocumentResponseCompound()
}

/**
 * @export 
 * A EzsigndocumentGetObjectV2ResponseMPayload Validation Object
 * @class ValidationObjectEzsigndocumentGetObjectV2ResponseMPayload
 */
export class ValidationObjectEzsigndocumentGetObjectV2ResponseMPayload {
   objEzsigndocument = new ValidationObjectEzsigndocumentResponseCompound()
} 


