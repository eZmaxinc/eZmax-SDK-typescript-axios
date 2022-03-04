/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.5
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { EzsignformfieldgroupRequestCompound } from './ezsignformfieldgroup-request-compound';

/**
 * Request for the /1/object/ezsignformfieldgroup/createObject API Request
 * @export
 * @interface EzsignformfieldgroupCreateObjectV1Request
 */
export interface EzsignformfieldgroupCreateObjectV1Request {
    /**
     * 
     * @type {Array<EzsignformfieldgroupRequestCompound>}
     * @memberof EzsignformfieldgroupCreateObjectV1Request
     */
    'a_objEzsignformfieldgroup': Array<EzsignformfieldgroupRequestCompound>;
}

