/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.8
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


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

