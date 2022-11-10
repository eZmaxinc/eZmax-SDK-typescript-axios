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
import { EzsignsignatureResponse } from './ezsignsignature-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignatureResponseCompoundAllOf } from './ezsignsignature-response-compound-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsignsignaturecustomdateResponseCompound } from './ezsignsignaturecustomdate-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignsignatureAttachmentnamesource } from './field-eezsignsignature-attachmentnamesource';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignsignatureFont } from './field-eezsignsignature-font';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignsignatureTooltipposition } from './field-eezsignsignature-tooltipposition';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEEzsignsignatureType } from './field-eezsignsignature-type';

import { DefaultObject } from '../base'

/**
 * @type EzsignsignatureResponseCompound
 * An Ezsignsignature Object and children to create a complete structure
 * @export
 */
export type EzsignsignatureResponseCompound = EzsignsignatureResponse & EzsignsignatureResponseCompoundAllOf;


/**
 * @export 
 * A EzsignsignatureResponseCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignsignatureResponseCompound
 */
export class DefaultObjectEzsignsignatureResponseCompound extends DefaultObject {
   pkiEzsignsignatureID:number = 0
   fkiEzsigndocumentID:number = 0
   fkiEzsignfoldersignerassociationID:number = 0
   iEzsignpagePagenumber:number = 0
   iEzsignsignatureX:number = 0
   iEzsignsignatureY:number = 0
   iEzsignsignatureStep:number = 0
   eEzsignsignatureType:FieldEEzsignsignatureType = 'Acknowledgement'
   tEzsignsignatureTooltip?:string = undefined
   eEzsignsignatureTooltipposition?:FieldEEzsignsignatureTooltipposition = undefined
   eEzsignsignatureFont?:FieldEEzsignsignatureFont = undefined
   iEzsignsignatureValidationstep?:number = undefined
   sEzsignsignatureAttachmentdescription?:string = undefined
   eEzsignsignatureAttachmentnamesource?:FieldEEzsignsignatureAttachmentnamesource = undefined
   bEzsignsignatureRequired?:boolean = undefined
   fkiEzsignfoldersignerassociationIDValidation?:number = undefined
   bEzsignsignatureCustomdate?:boolean = undefined
   a_objEzsignsignaturecustomdate?:Array<EzsignsignaturecustomdateResponseCompound> = undefined
}


