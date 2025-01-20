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
import type { EzsigndocumentRequest } from './ezsigndocument-request';

/**
 * Request for PUT /1/object/ezsigndocument/{pkiEzsigndocumentID}
 * @export
 * @interface EzsigndocumentEditObjectV1Request
 */
export interface EzsigndocumentEditObjectV1Request {
    /**
     * An Ezsigndocument Object and children to create a complete structure
     * @type {EzsigndocumentRequest}
     * @memberof EzsigndocumentEditObjectV1Request
     */
    /*'objEzsigndocument': EzsigndocumentRequest;*/
    'objEzsigndocument': EzsigndocumentRequest;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigndocumentRequest } from './'
// @ts-ignore
import { ValidationObjectEzsigndocumentRequest } from './'

/**
 * @export 
 * A EzsigndocumentEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigndocumentEditObjectV1Request
 */
export class DataObjectEzsigndocumentEditObjectV1Request {
   objEzsigndocument:EzsigndocumentRequest = new DataObjectEzsigndocumentRequest()
}

/**
 * @export 
 * A EzsigndocumentEditObjectV1Request Validation Object
 * @class ValidationObjectEzsigndocumentEditObjectV1Request
 */
export class ValidationObjectEzsigndocumentEditObjectV1Request {
   objEzsigndocument = new ValidationObjectEzsigndocumentRequest()
} 


