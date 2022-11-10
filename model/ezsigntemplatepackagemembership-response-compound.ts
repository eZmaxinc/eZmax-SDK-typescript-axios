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
import { EzsigntemplateResponseCompound } from './ezsigntemplate-response-compound';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackagemembershipResponse } from './ezsigntemplatepackagemembership-response';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackagemembershipResponseCompoundAllOf } from './ezsigntemplatepackagemembership-response-compound-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatepackagesignermembershipResponseCompound } from './ezsigntemplatepackagesignermembership-response-compound';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplatepackagemembershipResponseCompound
 * A Ezsigntemplatepackagemembership Object
 * @export
 */
export type EzsigntemplatepackagemembershipResponseCompound = EzsigntemplatepackagemembershipResponse & EzsigntemplatepackagemembershipResponseCompoundAllOf;


/**
 * @export 
 * A EzsigntemplatepackagemembershipResponseCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplatepackagemembershipResponseCompound
 */
export class DefaultObjectEzsigntemplatepackagemembershipResponseCompound extends DefaultObject {
   pkiEzsigntemplatepackagemembershipID:number = 0
   fkiEzsigntemplatepackageID:number = 0
   fkiEzsigntemplateID:number = 0
   iEzsigntemplatepackagemembershipOrder:number = 0
   objEzsigntemplate:Partial<EzsigntemplateResponseCompound> = {}
   a_objEzsigntemplatepackagesignermembership:Array<EzsigntemplatepackagesignermembershipResponseCompound> = []
}


