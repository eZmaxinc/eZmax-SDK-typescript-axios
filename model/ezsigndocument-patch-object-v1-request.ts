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
import type { EzsigndocumentRequestPatch } from './ezsigndocument-request-patch';

/**
 * Request for PATCH /1/object/ezsigndocument/{pkiEzsigndocumentID}
 * @export
 * @interface EzsigndocumentPatchObjectV1Request
 */
export interface EzsigndocumentPatchObjectV1Request {
    /**
     * 
     * @type {EzsigndocumentRequestPatch}
     * @memberof EzsigndocumentPatchObjectV1Request
     */
    /*'objEzsigndocument': EzsigndocumentRequestPatch;*/
    'objEzsigndocument': EzsigndocumentRequestPatch;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigndocumentRequestPatch } from './'
// @ts-ignore
import { ValidationObjectEzsigndocumentRequestPatch } from './'

/**
 * @export 
 * A EzsigndocumentPatchObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentPatchObjectV1Request
 */
export class DataObjectEzsigndocumentPatchObjectV1Request {
   objEzsigndocument:EzsigndocumentRequestPatch = new DataObjectEzsigndocumentRequestPatch()
}

/**
 * @export 
 * A EzsigndocumentPatchObjectV1Request Validation Object
 * @class ValidationObjectEzsigndocumentPatchObjectV1Request
 */
export class ValidationObjectEzsigndocumentPatchObjectV1Request {
   objEzsigndocument = new ValidationObjectEzsigndocumentRequestPatch()
} 


