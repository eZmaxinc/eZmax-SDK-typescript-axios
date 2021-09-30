/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


import { EzsignformfieldResponse } from './ezsignformfield-response';



/**
 * An Ezsignformfield Object and children to create a complete structure
 * @export
 * @interface EzsignformfieldResponseCompound
 */
export interface EzsignformfieldResponseCompound {
    /**
     * The Label for the Ezsignformfield
     * @type {string}
     * @memberof EzsignformfieldResponseCompound
     */
    sEzsignformfieldLabel: string;
    /**
     * The Value for the Ezsignformfield
     * @type {string}
     * @memberof EzsignformfieldResponseCompound
     */
    sEzsignformfieldValue: string;
}