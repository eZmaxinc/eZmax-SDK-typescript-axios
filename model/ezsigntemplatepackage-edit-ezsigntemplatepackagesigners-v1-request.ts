/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.10
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { EzsigntemplatepackagesignerRequestCompound } from './ezsigntemplatepackagesigner-request-compound';

/**
 * Request for PUT /1/object/ezsigntemplatepackage/{pkiEzsigntemplatepackageID}/editEzsigntemplatepackagesigners
 * @export
 * @interface EzsigntemplatepackageEditEzsigntemplatepackagesignersV1Request
 */
export interface EzsigntemplatepackageEditEzsigntemplatepackagesignersV1Request {
    /**
     * 
     * @type {Array<EzsigntemplatepackagesignerRequestCompound>}
     * @memberof EzsigntemplatepackageEditEzsigntemplatepackagesignersV1Request
     */
    'a_objEzsigntemplatepackagesigner': Array<EzsigntemplatepackagesignerRequestCompound>;
}

