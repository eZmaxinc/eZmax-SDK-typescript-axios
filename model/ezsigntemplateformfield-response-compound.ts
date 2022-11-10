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
import { EzsigntemplateformfieldResponse } from './ezsigntemplateformfield-response';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplateformfieldResponseCompound
 * An Ezsigntemplateformfield Object and children
 * @export
 */
export type EzsigntemplateformfieldResponseCompound = EzsigntemplateformfieldResponse;


/**
 * @export 
 * A EzsigntemplateformfieldResponseCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplateformfieldResponseCompound
 */
export class DefaultObjectEzsigntemplateformfieldResponseCompound extends DefaultObject {
   pkiEzsigntemplateformfieldID:number = 0
   iEzsigntemplatedocumentpagePagenumber:number = 0
   sEzsigntemplateformfieldLabel:string = ''
   sEzsigntemplateformfieldValue?:string = undefined
   iEzsigntemplateformfieldX:number = 0
   iEzsigntemplateformfieldY:number = 0
   iEzsigntemplateformfieldWidth:number = 0
   iEzsigntemplateformfieldHeight:number = 0
   bEzsigntemplateformfieldSelected?:boolean = undefined
}


