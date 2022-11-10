/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.16
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatedocumentpageResponse } from './ezsigntemplatedocumentpage-response';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplatedocumentpageResponseCompound
 * An Ezsigntemplatedocumentpage Object and children to create a complete structure
 * @export
 */
export type EzsigntemplatedocumentpageResponseCompound = EzsigntemplatedocumentpageResponse;


/**
 * @export 
 * A EzsigntemplatedocumentpageResponseCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplatedocumentpageResponseCompound
 */
export class DefaultObjectEzsigntemplatedocumentpageResponseCompound extends DefaultObject {
   pkiEzsigntemplatedocumentpageID:number = 0
   iEzsigntemplatedocumentpageWidthimage:number = 0
   iEzsigntemplatedocumentpageHeightimage:number = 0
   iEzsigntemplatedocumentpageWidthpdf:number = 0
   iEzsigntemplatedocumentpageHeightpdf:number = 0
   iEzsigntemplatedocumentpagePagenumber:number = 0
   sComputedImageurl:string = ''
}


