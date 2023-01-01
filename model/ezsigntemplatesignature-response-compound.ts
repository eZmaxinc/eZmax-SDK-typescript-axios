/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatesignatureResponse } from './ezsigntemplatesignature-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatesignatureResponseCompoundAllOf } from './ezsigntemplatesignature-response-compound-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatesignaturecustomdateResponseCompound } from './ezsigntemplatesignaturecustomdate-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplatesignatureAttachmentnamesource } from './field-eezsigntemplatesignature-attachmentnamesource';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplatesignatureFont } from './field-eezsigntemplatesignature-font';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplatesignatureTooltipposition } from './field-eezsigntemplatesignature-tooltipposition';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsigntemplatesignatureType } from './field-eezsigntemplatesignature-type';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplatesignatureResponseCompound
 * A Ezsigntemplatesignature Object
 * @export
 */
export type EzsigntemplatesignatureResponseCompound = EzsigntemplatesignatureResponse & EzsigntemplatesignatureResponseCompoundAllOf;


/**
 * @export 
 * A EzsigntemplatesignatureResponseCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplatesignatureResponseCompound
 */
export class DefaultObjectEzsigntemplatesignatureResponseCompound extends DefaultObject {
   pkiEzsigntemplatesignatureID:number = 0
   fkiEzsigntemplatedocumentID:number = 0
   fkiEzsigntemplatesignerID:number = 0
   fkiEzsigntemplatesignerIDValidation?:number = undefined
   iEzsigntemplatedocumentpagePagenumber:number = 0
   iEzsigntemplatesignatureX:number = 0
   iEzsigntemplatesignatureY:number = 0
   iEzsigntemplatesignatureStep:number = 0
   eEzsigntemplatesignatureType:FieldEEzsigntemplatesignatureType = 'Acknowledgement'
   tEzsigntemplatesignatureTooltip?:string = undefined
   eEzsigntemplatesignatureTooltipposition?:FieldEEzsigntemplatesignatureTooltipposition = undefined
   eEzsigntemplatesignatureFont?:FieldEEzsigntemplatesignatureFont = undefined
   iEzsigntemplatesignatureValidationstep?:number = undefined
   sEzsigntemplatesignatureAttachmentdescription?:string = undefined
   eEzsigntemplatesignatureAttachmentnamesource?:FieldEEzsigntemplatesignatureAttachmentnamesource = undefined
   bEzsigntemplatesignatureRequired?:boolean = undefined
   bEzsigntemplatesignatureCustomdate?:boolean = undefined
   a_objEzsigntemplatesignaturecustomdate?:Array<EzsigntemplatesignaturecustomdateResponseCompound> = undefined
}


