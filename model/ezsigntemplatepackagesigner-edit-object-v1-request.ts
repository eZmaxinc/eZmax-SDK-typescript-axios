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
import type { EzsigntemplatepackagesignerRequestCompound } from './ezsigntemplatepackagesigner-request-compound';

/**
 * Request for PUT /1/object/ezsigntemplatepackagesigner/{pkiEzsigntemplatepackagesignerID}
 * @export
 * @interface EzsigntemplatepackagesignerEditObjectV1Request
 */
export interface EzsigntemplatepackagesignerEditObjectV1Request {
    /**
     * 
     * @type {EzsigntemplatepackagesignerRequestCompound}
     * @memberof EzsigntemplatepackagesignerEditObjectV1Request
     */
    /*'objEzsigntemplatepackagesigner': EzsigntemplatepackagesignerRequestCompound;*/
    'objEzsigntemplatepackagesigner': EzsigntemplatepackagesignerRequestCompound;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectEzsigntemplatepackagesignerRequestCompound } from './'
// @ts-ignore
import { ValidationObjectEzsigntemplatepackagesignerRequestCompound } from './'

/**
 * @export 
 * A EzsigntemplatepackagesignerEditObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsigntemplatepackagesignerEditObjectV1Request
 */
export class DataObjectEzsigntemplatepackagesignerEditObjectV1Request {
   objEzsigntemplatepackagesigner:EzsigntemplatepackagesignerRequestCompound = new DataObjectEzsigntemplatepackagesignerRequestCompound()
}

/**
 * @export 
 * A EzsigntemplatepackagesignerEditObjectV1Request Validation Object
 * @class ValidationObjectEzsigntemplatepackagesignerEditObjectV1Request
 */
export class ValidationObjectEzsigntemplatepackagesignerEditObjectV1Request {
   objEzsigntemplatepackagesigner = new ValidationObjectEzsigntemplatepackagesignerRequestCompound()
} 


