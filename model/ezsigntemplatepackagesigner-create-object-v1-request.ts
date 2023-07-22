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
import { EzsigntemplatepackagesignerRequestCompound } from './ezsigntemplatepackagesigner-request-compound';

/**
 * Request for POST /1/object/ezsigntemplatepackagesigner
 * @export
 * @interface EzsigntemplatepackagesignerCreateObjectV1Request
 */
export interface EzsigntemplatepackagesignerCreateObjectV1Request {
    /**
     * 
     * @type {Array<EzsigntemplatepackagesignerRequestCompound>}
     * @memberof EzsigntemplatepackagesignerCreateObjectV1Request
     */
    'a_objEzsigntemplatepackagesigner': Array<EzsigntemplatepackagesignerRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsigntemplatepackagesignerCreateObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackagesignerCreateObjectV1Request
 */
export class DataObjectEzsigntemplatepackagesignerCreateObjectV1Request {
   a_objEzsigntemplatepackagesigner:Array<EzsigntemplatepackagesignerRequestCompound> = []
}

/**
 * @export 
 * A EzsigntemplatepackagesignerCreateObjectV1Request Validation Object
 * @class ValidationObjectEzsigntemplatepackagesignerCreateObjectV1Request
 */
export class ValidationObjectEzsigntemplatepackagesignerCreateObjectV1Request {
   a_objEzsigntemplatepackagesigner = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


